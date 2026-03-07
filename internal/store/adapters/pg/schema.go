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

	// 1. Obtener columnas existentes
	rows, err := r.conn.pool.Query(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_name = 'app_user'
	`)
	if err != nil {
		return fmt.Errorf("failed to get existing columns: %w", err)
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

	// 2. Iterar campos y aplicar cambios
	newFieldNames := make(map[string]bool)
	for _, field := range fields {
		// Use pgIdentifier to normalize field names (spaces -> underscores, remove accents, etc.)
		fieldName := pgIdentifier(field.Name)
		if fieldName == "" {
			log.Printf("Tenant %s: Skipping invalid field name: %s", tenantID, field.Name)
			continue
		}
		newFieldNames[fieldName] = true

		// Prevenir sobrescribir columnas de sistema
		if isSystemColumn(fieldName) {
			continue
		}

		// Mapear tipo
		sqlType := mapFieldTypeToSQL(field.Type)
		if sqlType == "" {
			log.Printf("Tenant %s: Unknown field type %s for field %s", tenantID, field.Type, fieldName)
			continue
		}

		// ADD COLUMN (use fieldName directly since pgIdentifier already validated it)
		if !existingCols[fieldName] {
			log.Printf("Tenant %s: Adding column %s (%s)", tenantID, fieldName, sqlType)
			query := fmt.Sprintf("ALTER TABLE app_user ADD COLUMN IF NOT EXISTS %s %s", fieldName, sqlType)
			if _, err := r.conn.pool.Exec(ctx, query); err != nil {
				return fmt.Errorf("failed to add column %s: %w", fieldName, err)
			}
		}

		// NOT NULL constraint - DISABLED to support social login flow
		_, _ = r.conn.pool.Exec(ctx, fmt.Sprintf("ALTER TABLE app_user ALTER COLUMN %s DROP NOT NULL", fieldName))

		// UNIQUE constraint
		uqName := fmt.Sprintf("uq_app_user_%s", fieldName)
		if field.Unique {
			query := fmt.Sprintf("ALTER TABLE app_user ADD CONSTRAINT %s UNIQUE (%s)", uqName, fieldName)
			_, err := r.conn.pool.Exec(ctx, query)
			if err != nil && !strings.Contains(err.Error(), "already exists") {
				log.Printf("Tenant %s: Failed to add unique constraint %s: %v", tenantID, uqName, err)
			}
		} else {
			// Drop constraint if exists
			_, _ = r.conn.pool.Exec(ctx, fmt.Sprintf("ALTER TABLE app_user DROP CONSTRAINT IF EXISTS %s", uqName))
		}

		// INDEX
		idxName := fmt.Sprintf("idx_app_user_%s", fieldName)
		if field.Indexed && !field.Unique {
			query := fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON app_user (%s)", idxName, fieldName)
			if _, err := r.conn.pool.Exec(ctx, query); err != nil {
				log.Printf("Tenant %s: Failed to create index %s: %v", tenantID, idxName, err)
			}
		} else if !field.Indexed {
			_, _ = r.conn.pool.Exec(ctx, fmt.Sprintf("DROP INDEX IF EXISTS %s", idxName))
		}
	}

	// 3. Drop removed columns
	for col := range existingCols {
		if isSystemColumn(col) {
			continue
		}
		if !newFieldNames[col] {
			log.Printf("Tenant %s: Dropping removed column %s", tenantID, col)
			if _, err := r.conn.pool.Exec(ctx, fmt.Sprintf("ALTER TABLE app_user DROP COLUMN IF EXISTS %s", col)); err != nil {
				return fmt.Errorf("failed to drop column %s: %w", col, err)
			}
		}
	}

	return nil
}

func (r *pgSchemaRepo) EnsureIndexes(ctx context.Context, tenantID string, schemaDef map[string]any) error {
	// Implementación simplificada (puerto directo de V1 si fuera necesario)
	// Por ahora solo SyncUserFields es critico.
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
