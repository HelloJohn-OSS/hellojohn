package mysql_shared

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"regexp"
	"strings"
	"unicode"

	"github.com/google/uuid"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// --- sharedSchemaRepo -------------------------------------------------------

type sharedSchemaRepo struct {
	db       *sql.DB
	tenantID uuid.UUID
}

var sharedValidIdentifier = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,49}$`)

// sharedMysqlIdentifier normalizes a field name into a safe MySQL identifier.
func sharedMysqlIdentifier(raw string) string {
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
		case r == '\u00e1' || r == '\u00e0' || r == '\u00e4' || r == '\u00e2' || r == '\u00e3':
			normalized.WriteRune('a')
		case r == '\u00e9' || r == '\u00e8' || r == '\u00eb' || r == '\u00ea':
			normalized.WriteRune('e')
		case r == '\u00ed' || r == '\u00ec' || r == '\u00ef' || r == '\u00ee':
			normalized.WriteRune('i')
		case r == '\u00f3' || r == '\u00f2' || r == '\u00f6' || r == '\u00f4' || r == '\u00f5':
			normalized.WriteRune('o')
		case r == '\u00fa' || r == '\u00f9' || r == '\u00fc' || r == '\u00fb':
			normalized.WriteRune('u')
		case r == '\u00f1':
			normalized.WriteRune('n')
		case r == '\u00e7':
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
		return "VARCHAR(500)"
	case "int", "integer", "number":
		return "BIGINT"
	case "bool", "boolean":
		return "TINYINT(1)"
	case "date", "datetime":
		return "DATETIME(6)"
	default:
		return "VARCHAR(500)"
	}
}

// columnExists checks whether a column already exists on the given table.
func columnExists(ctx context.Context, db *sql.DB, table, column string) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM information_schema.columns
		 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?`,
		table, column,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// indexExists checks whether an index already exists on the given table.
func indexExists(ctx context.Context, db *sql.DB, table, index string) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM information_schema.statistics
		 WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ?`,
		table, index,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *sharedSchemaRepo) SyncUserFields(ctx context.Context, _ string, fields []repository.UserFieldDefinition) error {
	if r.db == nil {
		return fmt.Errorf("mysql_shared schema repo: connection not initialized")
	}

	// Use first 8 hex chars of UUID (without dashes) as short tenant hash.
	// This keeps generated column names under 64-byte MySQL identifier limit:
	// cf_ (3) + 8 chars + _ (1) + fieldName (up to 50) = 62 max.
	tenantStr := strings.ReplaceAll(r.tenantID.String(), "-", "")[:8]

	// 1. Ensure custom_data JSON column exists (MySQL uses JSON, not JSONB).
	// MySQL 8.0 doesn't support ADD COLUMN IF NOT EXISTS, so check first.
	exists, err := columnExists(ctx, r.db, "app_user", "custom_data")
	if err != nil {
		return fmt.Errorf("mysql_shared: check custom_data column: %w", err)
	}
	if !exists {
		if _, err := r.db.ExecContext(ctx,
			`ALTER TABLE app_user ADD COLUMN custom_data JSON DEFAULT (JSON_OBJECT())`,
		); err != nil {
			return fmt.Errorf("mysql_shared: ensure custom_data column: %w", err)
		}
	}

	// 2. Get existing generated columns for THIS tenant (cf_{tenant}_{field} pattern)
	prefix := "cf_" + tenantStr + "_"
	existingGenCols := make(map[string]bool)
	rows, err := r.db.QueryContext(ctx, `
		SELECT COLUMN_NAME
		FROM information_schema.columns
		WHERE TABLE_NAME = 'app_user'
		  AND TABLE_SCHEMA = DATABASE()
		  AND COLUMN_NAME LIKE ?
	`, prefix+"%")
	if err != nil {
		return fmt.Errorf("mysql_shared: get existing generated columns: %w", err)
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

	// 3. Apply field changes.
	// MySQL DDL is NOT transactional — each ALTER TABLE commits immediately.
	// We execute statements sequentially, tolerating "already exists" errors.

	desiredGenCols := make(map[string]bool)
	for _, field := range fields {
		fieldName := sharedMysqlIdentifier(field.Name)
		if fieldName == "" {
			log.Printf("mysql_shared tenant %s: Skipping invalid field name: %s", r.tenantID, field.Name)
			continue
		}
		if sharedIsSystemColumn(fieldName) {
			continue
		}

		genCol := fmt.Sprintf("cf_%s_%s", tenantStr, fieldName)
		sqlType := sharedMapFieldTypeToSQL(field.Type)

		if field.Unique {
			// Unique: generated stored column + UNIQUE INDEX(tenant_id, cf_col)
			desiredGenCols[genCol] = true

			if !existingGenCols[genCol] {
				log.Printf("mysql_shared tenant %s: Adding generated column %s for unique field %s", r.tenantID, genCol, fieldName)
				query := fmt.Sprintf(
					"ALTER TABLE app_user ADD COLUMN %s %s GENERATED ALWAYS AS (JSON_UNQUOTE(JSON_EXTRACT(custom_data, '$.%s'))) STORED",
					genCol, sqlType, fieldName,
				)
				if _, err := r.db.ExecContext(ctx, query); err != nil {
					return fmt.Errorf("mysql_shared: add generated column %s: %w", genCol, err)
				}
			}

			uqName := fmt.Sprintf("uq_cf_%s_%s", tenantStr, fieldName)
			ok, _ := indexExists(ctx, r.db, "app_user", uqName)
			if !ok {
				query := fmt.Sprintf("ALTER TABLE app_user ADD UNIQUE INDEX %s (tenant_id, %s)", uqName, genCol)
				if _, err := r.db.ExecContext(ctx, query); err != nil {
					log.Printf("mysql_shared tenant %s: Failed to add unique index %s: %v", r.tenantID, uqName, err)
				}
			}

			// Drop expression index if field changed from indexed to unique
			idxName := fmt.Sprintf("idx_cf_%s_%s", tenantStr, fieldName)
			if ok, _ := indexExists(ctx, r.db, "app_user", idxName); ok {
				_, _ = r.db.ExecContext(ctx, fmt.Sprintf("DROP INDEX %s ON app_user", idxName))
			}

		} else if field.Indexed {
			// Indexed (non-unique): expression index on custom_data JSON path.
			// MySQL requires expressions wrapped in extra parens and CAST for indexing.
			idxName := fmt.Sprintf("idx_cf_%s_%s", tenantStr, fieldName)
			if ok, _ := indexExists(ctx, r.db, "app_user", idxName); !ok {
				query := fmt.Sprintf(
					"CREATE INDEX %s ON app_user ((CAST(JSON_UNQUOTE(JSON_EXTRACT(custom_data, '$.%s')) AS CHAR(255))))",
					idxName, fieldName,
				)
				if _, err := r.db.ExecContext(ctx, query); err != nil {
					log.Printf("mysql_shared tenant %s: Failed to create expression index %s: %v", r.tenantID, idxName, err)
				}
			}

			// Drop unique index + generated column if field changed from unique to indexed
			uqName := fmt.Sprintf("uq_cf_%s_%s", tenantStr, fieldName)
			if ok, _ := indexExists(ctx, r.db, "app_user", uqName); ok {
				_, _ = r.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE app_user DROP INDEX %s", uqName))
			}
			if existingGenCols[genCol] {
				_, _ = r.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE app_user DROP COLUMN %s", genCol))
			}
		} else {
			// Plain field — clean up constraints/columns
			idxName := fmt.Sprintf("idx_cf_%s_%s", tenantStr, fieldName)
			if ok, _ := indexExists(ctx, r.db, "app_user", idxName); ok {
				_, _ = r.db.ExecContext(ctx, fmt.Sprintf("DROP INDEX %s ON app_user", idxName))
			}
			uqName := fmt.Sprintf("uq_cf_%s_%s", tenantStr, fieldName)
			if ok, _ := indexExists(ctx, r.db, "app_user", uqName); ok {
				_, _ = r.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE app_user DROP INDEX %s", uqName))
			}
			if existingGenCols[genCol] {
				_, _ = r.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE app_user DROP COLUMN %s", genCol))
			}
		}
	}

	// 4. Drop generated columns for fields removed from definition.
	// Generated columns are derived from custom_data — safe to drop (no data loss).
	allValidGenCols := make(map[string]bool)
	for _, field := range fields {
		fieldName := sharedMysqlIdentifier(field.Name)
		if fieldName != "" {
			allValidGenCols[fmt.Sprintf("cf_%s_%s", tenantStr, fieldName)] = true
		}
	}
	for col := range existingGenCols {
		if !allValidGenCols[col] {
			log.Printf("mysql_shared tenant %s: Dropping removed generated column %s", r.tenantID, col)
			// Extract field name from cf_{tenant}_{field}
			fieldName := strings.TrimPrefix(col, prefix)
			uqName := fmt.Sprintf("uq_cf_%s_%s", tenantStr, fieldName)
			if ok, _ := indexExists(ctx, r.db, "app_user", uqName); ok {
				_, _ = r.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE app_user DROP INDEX %s", uqName))
			}
			idxName := fmt.Sprintf("idx_cf_%s_%s", tenantStr, fieldName)
			if ok, _ := indexExists(ctx, r.db, "app_user", idxName); ok {
				_, _ = r.db.ExecContext(ctx, fmt.Sprintf("DROP INDEX %s ON app_user", idxName))
			}
			if _, err := r.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE app_user DROP COLUMN %s", col)); err != nil {
				return fmt.Errorf("mysql_shared: drop generated column %s: %w", col, err)
			}
		}
	}

	return nil
}

func (r *sharedSchemaRepo) EnsureIndexes(_ context.Context, _ string, _ map[string]any) error {
	return nil
}

func (r *sharedSchemaRepo) IntrospectColumns(ctx context.Context, _, tableName string) ([]repository.ColumnInfo, error) {
	const query = `
		SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT
		FROM information_schema.columns
		WHERE TABLE_NAME = ?
		  AND TABLE_SCHEMA = DATABASE()
		ORDER BY ORDINAL_POSITION
	`
	rows, err := r.db.QueryContext(ctx, query, tableName)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: introspect columns: %w", err)
	}
	defer rows.Close()

	var columns []repository.ColumnInfo
	for rows.Next() {
		var col repository.ColumnInfo
		var isNullable string
		var columnDefault *string
		if err := rows.Scan(&col.Name, &col.DataType, &isNullable, &columnDefault); err != nil {
			return nil, fmt.Errorf("mysql_shared: scan column: %w", err)
		}
		col.IsNullable = isNullable == "YES"
		if columnDefault != nil {
			col.Default = *columnDefault
		}
		columns = append(columns, col)
	}
	return columns, rows.Err()
}

