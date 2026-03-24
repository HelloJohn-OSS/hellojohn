package pg

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// pgSchemaRepo implementa repository.SchemaRepository para PostgreSQL.
type pgSchemaRepo struct {
	conn *pgConnection
}

func (r *pgSchemaRepo) SyncUserFields(ctx context.Context, tenantID string, fields []repository.UserFieldDefinition) error {
	if r.conn == nil || r.conn.pool == nil {
		return fmt.Errorf("pg schema repo: connection not initialized")
	}

	// 1. Ensure custom_data JSONB column exists (idempotent — should be in migration, but be safe)
	if _, err := r.conn.pool.Exec(ctx,
		`ALTER TABLE app_user ADD COLUMN IF NOT EXISTS custom_data JSONB DEFAULT '{}'::jsonb`,
	); err != nil {
		return fmt.Errorf("pg: ensure custom_data column: %w", err)
	}

	// 2. Get existing generated columns (cf_* prefix) and their constraints/indexes
	existingGenCols := make(map[string]bool)
	rows, err := r.conn.pool.Query(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_name = 'app_user'
		  AND column_name LIKE 'cf_%'
	`)
	if err != nil {
		return fmt.Errorf("pg: get existing generated columns: %w", err)
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
	tx, err := r.conn.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pg: begin schema tx: %w", err)
	}
	defer tx.Rollback(ctx)

	desiredGenCols := make(map[string]bool)
	for _, field := range fields {
		fieldName := pgIdentifier(field.Name)
		if fieldName == "" {
			log.Printf("Tenant %s: Skipping invalid field name: %s", tenantID, field.Name)
			continue
		}
		if isSystemColumn(fieldName) {
			continue
		}

		genCol := "cf_" + fieldName
		sqlType := mapFieldTypeToSQL(field.Type)

		if field.Unique {
			// Unique fields need a generated stored column + UNIQUE constraint
			desiredGenCols[genCol] = true

			if !existingGenCols[genCol] {
				log.Printf("Tenant %s: Adding generated column %s for unique field %s", tenantID, genCol, fieldName)
				query := fmt.Sprintf(
					"ALTER TABLE app_user ADD COLUMN %s %s GENERATED ALWAYS AS (custom_data->>'%s') STORED",
					genCol, sqlType, fieldName,
				)
				if _, err := tx.Exec(ctx, query); err != nil {
					return fmt.Errorf("pg: add generated column %s: %w", genCol, err)
				}
			}

			// Add UNIQUE constraint (idempotent via IF NOT EXISTS-style error check)
			uqName := fmt.Sprintf("uq_cf_%s", fieldName)
			query := fmt.Sprintf("ALTER TABLE app_user ADD CONSTRAINT %s UNIQUE (%s)", uqName, genCol)
			_, err := tx.Exec(ctx, query)
			if err != nil && !strings.Contains(err.Error(), "already exists") {
				log.Printf("Tenant %s: Failed to add unique constraint %s: %v", tenantID, uqName, err)
			}

			// Drop any expression index for this field (may have changed from indexed to unique)
			idxName := fmt.Sprintf("idx_cf_%s", fieldName)
			_, _ = tx.Exec(ctx, fmt.Sprintf("DROP INDEX IF EXISTS %s", idxName))

		} else if field.Indexed {
			// Indexed (non-unique) fields use expression indexes — no generated column needed
			idxName := fmt.Sprintf("idx_cf_%s", fieldName)
			query := fmt.Sprintf(
				"CREATE INDEX IF NOT EXISTS %s ON app_user ((custom_data->>'%s'))",
				idxName, fieldName,
			)
			if _, err := tx.Exec(ctx, query); err != nil {
				log.Printf("Tenant %s: Failed to create expression index %s: %v", tenantID, idxName, err)
			}

			// Drop unique constraint + generated column if field changed from unique to indexed
			uqName := fmt.Sprintf("uq_cf_%s", fieldName)
			_, _ = tx.Exec(ctx, fmt.Sprintf("ALTER TABLE app_user DROP CONSTRAINT IF EXISTS %s", uqName))
			if existingGenCols[genCol] {
				_, _ = tx.Exec(ctx, fmt.Sprintf("ALTER TABLE app_user DROP COLUMN IF EXISTS %s", genCol))
			}
		} else {
			// Plain field — no index, no generated column. Clean up if it had them.
			idxName := fmt.Sprintf("idx_cf_%s", fieldName)
			_, _ = tx.Exec(ctx, fmt.Sprintf("DROP INDEX IF EXISTS %s", idxName))
			uqName := fmt.Sprintf("uq_cf_%s", fieldName)
			_, _ = tx.Exec(ctx, fmt.Sprintf("ALTER TABLE app_user DROP CONSTRAINT IF EXISTS %s", uqName))
			if existingGenCols[genCol] {
				_, _ = tx.Exec(ctx, fmt.Sprintf("ALTER TABLE app_user DROP COLUMN IF EXISTS %s", genCol))
			}
		}
	}

	// 4. Drop generated columns for fields removed from definition
	// Build set of all valid cf_ column names from current fields
	allValidGenCols := make(map[string]bool)
	for _, field := range fields {
		fieldName := pgIdentifier(field.Name)
		if fieldName != "" {
			allValidGenCols["cf_"+fieldName] = true
		}
	}
	for col := range existingGenCols {
		if !allValidGenCols[col] {
			log.Printf("Tenant %s: Dropping removed generated column %s", tenantID, col)
			// Drop constraint first (may or may not exist)
			fieldName := strings.TrimPrefix(col, "cf_")
			uqName := fmt.Sprintf("uq_cf_%s", fieldName)
			_, _ = tx.Exec(ctx, fmt.Sprintf("ALTER TABLE app_user DROP CONSTRAINT IF EXISTS %s", uqName))
			idxName := fmt.Sprintf("idx_cf_%s", fieldName)
			_, _ = tx.Exec(ctx, fmt.Sprintf("DROP INDEX IF EXISTS %s", idxName))
			// Drop the generated column
			if _, err := tx.Exec(ctx, fmt.Sprintf("ALTER TABLE app_user DROP COLUMN IF EXISTS %s", col)); err != nil {
				return fmt.Errorf("pg: drop generated column %s: %w", col, err)
			}
		}
	}

	return tx.Commit(ctx)
}

func (r *pgSchemaRepo) EnsureIndexes(ctx context.Context, tenantID string, schemaDef map[string]any) error {
	// Not needed — SyncUserFields handles indexes.
	return nil
}

func (r *pgSchemaRepo) IntrospectColumns(ctx context.Context, tenantID, tableName string) ([]repository.ColumnInfo, error) {
	const query = `
		SELECT column_name, data_type, is_nullable, column_default
		FROM information_schema.columns
		WHERE table_name = $1
		ORDER BY ordinal_position
	`
	rows, err := r.conn.pool.Query(ctx, query, tableName)
	if err != nil {
		return nil, fmt.Errorf("pg: introspect columns: %w", err)
	}
	defer rows.Close()

	var columns []repository.ColumnInfo
	for rows.Next() {
		var col repository.ColumnInfo
		var isNullable string
		var columnDefault *string
		if err := rows.Scan(&col.Name, &col.DataType, &isNullable, &columnDefault); err != nil {
			return nil, fmt.Errorf("pg: scan column: %w", err)
		}
		col.IsNullable = isNullable == "YES"
		if columnDefault != nil {
			col.Default = *columnDefault
		}
		columns = append(columns, col)
	}
	return columns, rows.Err()
}

// ─── Helpers ───

// isSystemColumn is defined in adapter.go

func mapFieldTypeToSQL(t string) string {
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
