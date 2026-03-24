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

var sharedValidIdentifier = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,49}$`)

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
		"name", "given_name", "family_name", "picture", "locale", "language", "source_client_id",
		"custom_data":
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

	// Use first 8 hex chars of UUID (without dashes) as short tenant hash.
	// This keeps generated column names under 63-byte PG identifier limit:
	// cf_ (3) + 8 chars + _ (1) + fieldName (up to 50) = 62 max.
	tenantStr := strings.ReplaceAll(r.tenantID.String(), "-", "")[:8]

	// 1. Ensure custom_data JSONB column exists (idempotent)
	if _, err := r.pool.Exec(ctx,
		`ALTER TABLE app_user ADD COLUMN IF NOT EXISTS custom_data JSONB DEFAULT '{}'::jsonb`,
	); err != nil {
		return fmt.Errorf("pg_shared: ensure custom_data column: %w", err)
	}

	// 2. Get existing generated columns for THIS tenant (cf_{tenant}_{field} pattern)
	prefix := "cf_" + tenantStr + "_"
	existingGenCols := make(map[string]bool)
	rows, err := r.pool.Query(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_name = 'app_user'
		  AND table_schema = 'public'
		  AND column_name LIKE $1
	`, prefix+"%")
	if err != nil {
		return fmt.Errorf("pg_shared: get existing generated columns: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			return err
		}
		existingGenCols[col] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// 3. Apply field changes inside a transaction (PostgreSQL DDL is transactional)
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pg_shared: begin schema tx: %w", err)
	}
	defer tx.Rollback(ctx)

	desiredGenCols := make(map[string]bool)
	for _, field := range fields {
		fieldName := sharedPgIdentifier(field.Name)
		if fieldName == "" {
			log.Printf("pg_shared tenant %s: Skipping invalid field name: %s", r.tenantID, field.Name)
			continue
		}
		if sharedIsSystemColumn(fieldName) {
			continue
		}

		genCol := fmt.Sprintf("cf_%s_%s", tenantStr, fieldName)
		sqlType := sharedMapFieldTypeToSQL(field.Type)

		if field.Unique {
			// Unique: generated stored column + UNIQUE(tenant_id, cf_col)
			desiredGenCols[genCol] = true

			if !existingGenCols[genCol] {
				log.Printf("pg_shared tenant %s: Adding generated column %s for unique field %s", r.tenantID, genCol, fieldName)
				query := fmt.Sprintf(
					"ALTER TABLE app_user ADD COLUMN %s %s GENERATED ALWAYS AS (custom_data->>'%s') STORED",
					genCol, sqlType, fieldName,
				)
				if _, err := tx.Exec(ctx, query); err != nil {
					return fmt.Errorf("pg_shared: add generated column %s: %w", genCol, err)
				}
			}

			uqName := fmt.Sprintf("uq_cf_%s_%s", tenantStr, fieldName)
			query := fmt.Sprintf("ALTER TABLE app_user ADD CONSTRAINT %s UNIQUE (tenant_id, %s)", uqName, genCol)
			_, err := tx.Exec(ctx, query)
			if err != nil && !strings.Contains(err.Error(), "already exists") {
				log.Printf("pg_shared tenant %s: Failed to add unique constraint %s: %v", r.tenantID, uqName, err)
			}

			// Drop expression index if field changed from indexed to unique
			idxName := fmt.Sprintf("idx_cf_%s_%s", tenantStr, fieldName)
			_, _ = tx.Exec(ctx, fmt.Sprintf("DROP INDEX IF EXISTS %s", idxName))

		} else if field.Indexed {
			// Indexed (non-unique): partial expression index scoped to this tenant
			idxName := fmt.Sprintf("idx_cf_%s_%s", tenantStr, fieldName)
			query := fmt.Sprintf(
				"CREATE INDEX IF NOT EXISTS %s ON app_user ((custom_data->>'%s')) WHERE tenant_id = '%s'",
				idxName, fieldName, r.tenantID.String(),
			)
			if _, err := tx.Exec(ctx, query); err != nil {
				log.Printf("pg_shared tenant %s: Failed to create expression index %s: %v", r.tenantID, idxName, err)
			}

			// Drop unique constraint + generated column if field changed from unique to indexed
			uqName := fmt.Sprintf("uq_cf_%s_%s", tenantStr, fieldName)
			_, _ = tx.Exec(ctx, fmt.Sprintf("ALTER TABLE app_user DROP CONSTRAINT IF EXISTS %s", uqName))
			if existingGenCols[genCol] {
				_, _ = tx.Exec(ctx, fmt.Sprintf("ALTER TABLE app_user DROP COLUMN IF EXISTS %s", genCol))
			}
		} else {
			// Plain field — clean up constraints/columns
			idxName := fmt.Sprintf("idx_cf_%s_%s", tenantStr, fieldName)
			_, _ = tx.Exec(ctx, fmt.Sprintf("DROP INDEX IF EXISTS %s", idxName))
			uqName := fmt.Sprintf("uq_cf_%s_%s", tenantStr, fieldName)
			_, _ = tx.Exec(ctx, fmt.Sprintf("ALTER TABLE app_user DROP CONSTRAINT IF EXISTS %s", uqName))
			if existingGenCols[genCol] {
				_, _ = tx.Exec(ctx, fmt.Sprintf("ALTER TABLE app_user DROP COLUMN IF EXISTS %s", genCol))
			}
		}
	}

	// 4. Drop generated columns for fields removed from definition.
	// Generated columns are derived from custom_data — safe to drop (no data loss).
	allValidGenCols := make(map[string]bool)
	for _, field := range fields {
		fieldName := sharedPgIdentifier(field.Name)
		if fieldName != "" {
			allValidGenCols[fmt.Sprintf("cf_%s_%s", tenantStr, fieldName)] = true
		}
	}
	for col := range existingGenCols {
		if !allValidGenCols[col] {
			log.Printf("pg_shared tenant %s: Dropping removed generated column %s", r.tenantID, col)
			// Extract field name from cf_{tenant}_{field}
			fieldName := strings.TrimPrefix(col, prefix)
			uqName := fmt.Sprintf("uq_cf_%s_%s", tenantStr, fieldName)
			_, _ = tx.Exec(ctx, fmt.Sprintf("ALTER TABLE app_user DROP CONSTRAINT IF EXISTS %s", uqName))
			idxName := fmt.Sprintf("idx_cf_%s_%s", tenantStr, fieldName)
			_, _ = tx.Exec(ctx, fmt.Sprintf("DROP INDEX IF EXISTS %s", idxName))
			if _, err := tx.Exec(ctx, fmt.Sprintf("ALTER TABLE app_user DROP COLUMN IF EXISTS %s", col)); err != nil {
				return fmt.Errorf("pg_shared: drop generated column %s: %w", col, err)
			}
		}
	}

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
