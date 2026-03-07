package pg_shared

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// ─── sharedSchemaRepo ─────────────────────────────────────────────

type sharedSchemaRepo struct {
	pool     *pgxpool.Pool
	tenantID uuid.UUID
}

var sharedValidIdentifier = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// sharedPgIdentifier normalizes a field name into a safe PG identifier.
func sharedPgIdentifier(raw string) string {
	name := strings.TrimSpace(strings.ToLower(raw))
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "-", "_")

	var normalized strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			normalized.WriteRune(r)
		case r == '_':
			normalized.WriteRune(r)
		case r == 'á' || r == 'à' || r == 'ä' || r == 'â' || r == 'ã':
			normalized.WriteRune('a')
		case r == 'é' || r == 'è' || r == 'ë' || r == 'ê':
			normalized.WriteRune('e')
		case r == 'í' || r == 'ì' || r == 'ï' || r == 'î':
			normalized.WriteRune('i')
		case r == 'ó' || r == 'ò' || r == 'ö' || r == 'ô' || r == 'õ':
			normalized.WriteRune('o')
		case r == 'ú' || r == 'ù' || r == 'ü' || r == 'û':
			normalized.WriteRune('u')
		case r == 'ñ':
			normalized.WriteRune('n')
		case r == 'ç':
			normalized.WriteRune('c')
		default:
			if unicode.IsLetter(r) {
				// skip unrecognized
			}
		}
	}
	name = normalized.String()

	if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
		name = "_" + name
	}
	if !sharedValidIdentifier.MatchString(name) || name == "" {
		return ""
	}
	return name
}

func sharedIsSystemColumn(name string) bool {
	switch name {
	case "id", "tenant_id", "email", "email_verified", "status", "profile", "metadata",
		"disabled_at", "disabled_reason", "disabled_until",
		"created_at", "updated_at", "password_hash",
		"name", "given_name", "family_name", "picture", "locale", "language", "source_client_id":
		return true
	}
	return false
}

func sharedMapFieldTypeToSQL(t string) string {
	switch t {
	case "text", "string", "phone", "country":
		return "TEXT"
	case "int", "integer", "number":
		return "BIGINT"
	case "bool", "boolean":
		return "BOOLEAN"
	case "date", "datetime":
		return "TIMESTAMPTZ"
	default:
		return "TEXT"
	}
}

func (r *sharedSchemaRepo) SyncUserFields(ctx context.Context, _ string, fields []repository.UserFieldDefinition) error {
	if r.pool == nil {
		return fmt.Errorf("pg_shared schema repo: connection not initialized")
	}

	// 1. Get existing columns
	rows, err := r.pool.Query(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_name = 'app_user'
		  AND table_schema = 'public'
	`)
	if err != nil {
		return fmt.Errorf("pg_shared: failed to get existing columns: %w", err)
	}
	defer rows.Close()

	existingCols := make(map[string]bool)
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			return err
		}
		existingCols[col] = true
	}

	// 2. Apply field changes inside a transaction so partial DDL is rolled back on failure.
	// PostgreSQL DDL is transactional — ALTER TABLE, ADD CONSTRAINT, CREATE/DROP INDEX
	// are all rolled back atomically if the transaction aborts.
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pg_shared: begin schema tx: %w", err)
	}
	defer tx.Rollback(ctx)

	newFieldNames := make(map[string]bool)
	for _, field := range fields {
		fieldName := sharedPgIdentifier(field.Name)
		if fieldName == "" {
			log.Printf("pg_shared tenant %s: Skipping invalid field name: %s", r.tenantID, field.Name)
			continue
		}
		newFieldNames[fieldName] = true

		if sharedIsSystemColumn(fieldName) {
			continue
		}

		sqlType := sharedMapFieldTypeToSQL(field.Type)
		if sqlType == "" {
			log.Printf("pg_shared tenant %s: Unknown field type %s for field %s", r.tenantID, field.Type, fieldName)
			continue
		}

		if !existingCols[fieldName] {
			log.Printf("pg_shared tenant %s: Adding column %s (%s)", r.tenantID, fieldName, sqlType)
			query := fmt.Sprintf("ALTER TABLE app_user ADD COLUMN IF NOT EXISTS %s %s", fieldName, sqlType)
			if _, err := tx.Exec(ctx, query); err != nil {
				return fmt.Errorf("pg_shared: failed to add column %s: %w", fieldName, err)
			}
		}

		// Drop NOT NULL for social login compat
		if _, err := tx.Exec(ctx, fmt.Sprintf("ALTER TABLE app_user ALTER COLUMN %s DROP NOT NULL", fieldName)); err != nil {
			log.Printf("[WARN] pg_shared: drop not null for %s: %v", fieldName, err)
		}

		// UNIQUE constraint (tenant-scoped for shared table)
		// NOTE: Replace hyphens with underscores — PostgreSQL identifiers cannot contain hyphens.
		tenantStr := strings.ReplaceAll(r.tenantID.String(), "-", "_")
		uqName := fmt.Sprintf("uq_app_user_%s_%s", tenantStr, fieldName)
		if field.Unique {
			query := fmt.Sprintf("ALTER TABLE app_user ADD CONSTRAINT %s UNIQUE (tenant_id, %s)", uqName, fieldName)
			_, err := tx.Exec(ctx, query)
			if err != nil && !strings.Contains(err.Error(), "already exists") {
				log.Printf("pg_shared tenant %s: Failed to add unique constraint %s: %v", r.tenantID, uqName, err)
			}
		} else {
			_, _ = tx.Exec(ctx, fmt.Sprintf("ALTER TABLE app_user DROP CONSTRAINT IF EXISTS %s", uqName))
		}

		// INDEX (tenant-scoped for efficient queries)
		idxName := fmt.Sprintf("idx_app_user_%s_%s", tenantStr, fieldName)
		if field.Indexed && !field.Unique {
			query := fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON app_user (tenant_id, %s)", idxName, fieldName)
			if _, err := tx.Exec(ctx, query); err != nil {
				log.Printf("pg_shared tenant %s: Failed to create index %s: %v", r.tenantID, idxName, err)
			}
		} else if !field.Indexed {
			_, _ = tx.Exec(ctx, fmt.Sprintf("DROP INDEX IF EXISTS %s", idxName))
		}
	}

	// 3. In shared mode, NEVER drop columns — other tenants may use them.
	// Custom columns accumulate; cleanup requires explicit admin action.
	// This is a fundamental constraint of shared-table multi-tenancy.
	// (Isolated pg adapter can safely drop columns since it owns the table.)

	return tx.Commit(ctx)
}

func (r *sharedSchemaRepo) EnsureIndexes(_ context.Context, _ string, _ map[string]any) error {
	return nil
}

func (r *sharedSchemaRepo) IntrospectColumns(ctx context.Context, _, tableName string) ([]repository.ColumnInfo, error) {
	const query = `
		SELECT column_name, data_type, is_nullable, column_default
		FROM information_schema.columns
		WHERE table_name = $1
		  AND table_schema = 'public'
		ORDER BY ordinal_position
	`
	rows, err := r.pool.Query(ctx, query, tableName)
	if err != nil {
		return nil, fmt.Errorf("pg_shared: introspect columns: %w", err)
	}
	defer rows.Close()

	var columns []repository.ColumnInfo
	for rows.Next() {
		var col repository.ColumnInfo
		var isNullable string
		var columnDefault *string
		if err := rows.Scan(&col.Name, &col.DataType, &isNullable, &columnDefault); err != nil {
			return nil, fmt.Errorf("pg_shared: scan column: %w", err)
		}
		col.IsNullable = isNullable == "YES"
		if columnDefault != nil {
			col.Default = *columnDefault
		}
		columns = append(columns, col)
	}
	return columns, rows.Err()
}

// ─── DeleteAllForTenant ──────────────────────────────────────────
// Cascade-deletes ALL data for a tenant from the shared database.
// Used for tenant deprovisioning/cleanup.

func DeleteAllForTenant(ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID) error {
	return execWithRLS(ctx, pool, tenantID, func(tx pgx.Tx) error {
		// Delete in FK-safe order (reverse of creation)
		tables := []string{
			"password_history",
			"webauthn_credential",
			"invitation",
			"webhook_delivery",
			"webhook",
			"audit_log",
			"sessions",
			"user_consent",
			"mfa_trusted_device",
			"mfa_recovery_code",
			"mfa_totp",
			"password_reset_token",
			"email_verification_token",
			"rbac_user_role",
			"rbac_role",
			"refresh_token",
			"identity",
			"app_user",
		}

		for _, table := range tables {
			_, err := tx.Exec(ctx, fmt.Sprintf("DELETE FROM %s WHERE tenant_id = $1", table), tenantID)
			if err != nil {
				return fmt.Errorf("pg_shared: delete %s for tenant %s: %w", table, tenantID, err)
			}
		}

		return nil
	})
}
