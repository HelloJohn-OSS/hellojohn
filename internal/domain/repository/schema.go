package repository

import (
	"context"
)

// ColumnInfo representa metadata de una columna de base de datos.
type ColumnInfo struct {
	Name       string // Nombre de la columna
	DataType   string // Tipo de dato (TEXT, INTEGER, BOOLEAN, etc)
	IsNullable bool   // Si permite NULL
	Default    string // Valor default (puede estar vacío)
}

// SchemaRepository define operaciones para manipular el esquema de la base de datos
// de un tenant en tiempo de ejecución (ej: custom fields).
type SchemaRepository interface {
	// SyncUserFields sincroniza la tabla de usuarios con la definición de campos custom.
	// Crea columnas faltantes, índices y constraints.
	SyncUserFields(ctx context.Context, tenantID string, fields []UserFieldDefinition) error

	// EnsureIndexes asegura que existan los índices definidos.
	EnsureIndexes(ctx context.Context, tenantID string, schemaDef map[string]any) error

	// IntrospectColumns retorna la lista de columnas de una tabla.
	// Útil para handlers que necesitan conocer campos dinámicos.
	IntrospectColumns(ctx context.Context, tenantID, tableName string) ([]ColumnInfo, error)
}
