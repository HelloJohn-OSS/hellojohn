// Package mysql contiene utilidades compartidas para los repositorios MySQL.
package mysql

import (
	"database/sql"
	"encoding/json"
	"regexp"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Conversión de tipos NULL
// MySQL usa sql.NullXXX types para manejar valores NULL.
// ─────────────────────────────────────────────────────────────────────────────

// nullIfEmpty returns sql.NullString for optional string fields.
// Si el string está vacío, retorna un NullString inválido (NULL en DB).
func nullIfEmpty(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// ptrToNullString convierte *string a sql.NullString.
func ptrToNullString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

// nullStringToPtr convierte sql.NullString a *string.
func nullStringToPtr(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	return &ns.String
}

// ptrToNullTime convierte *time.Time a sql.NullTime.
func ptrToNullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

// nullTimeToPtr convierte sql.NullTime a *time.Time.
func nullTimeToPtr(nt sql.NullTime) *time.Time {
	if !nt.Valid {
		return nil
	}
	return &nt.Time
}

// ptrToNullInt64 convierte *int a sql.NullInt64.
func ptrToNullInt64(i *int) sql.NullInt64 {
	if i == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*i), Valid: true}
}

// nullInt64ToPtr convierte sql.NullInt64 a *int.
func nullInt64ToPtr(ni sql.NullInt64) *int {
	if !ni.Valid {
		return nil
	}
	i := int(ni.Int64)
	return &i
}

// ─────────────────────────────────────────────────────────────────────────────
// Conversión de JSON Arrays
// MySQL almacena arrays como JSON, mientras PostgreSQL usa TEXT[].
// ─────────────────────────────────────────────────────────────────────────────

// jsonToStrings parsea un JSON array a []string.
// Retorna nil si el input está vacío o es inválido.
func jsonToStrings(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	var result []string
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	return result
}

// stringsToJSON convierte []string a JSON bytes.
// Retorna "[]" si el slice es nil.
func stringsToJSON(arr []string) []byte {
	if arr == nil {
		arr = []string{}
	}
	data, _ := json.Marshal(arr)
	return data
}

// mapToJSON convierte map[string]any a JSON bytes.
func mapToJSON(m map[string]any) []byte {
	if m == nil {
		return []byte("{}")
	}
	data, err := json.Marshal(m)
	if err != nil {
		return []byte("{}")
	}
	return data
}

// jsonToMap parsea JSON a map[string]any.
func jsonToMap(data []byte) map[string]any {
	if len(data) == 0 {
		return nil
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	return result
}

// ─────────────────────────────────────────────────────────────────────────────
// Identificadores SQL seguros
// Previene SQL injection al sanitizar nombres de columnas dinámicos.
// ─────────────────────────────────────────────────────────────────────────────

// validIdentifier regex para validar identificadores MySQL.
// Solo permite letras minúsculas, números y underscores.
// Debe empezar con letra o underscore.
var validIdentifier = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// mysqlIdentifier sanitiza un string para usarlo como identificador MySQL.
// Elimina caracteres especiales y normaliza a minúsculas.
// Retorna string vacío si el resultado no es válido.
func mysqlIdentifier(name string) string {
	// Normalizar: lowercase, trim, espacios a underscores
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.ReplaceAll(name, " ", "_")

	// Remover acentos y caracteres especiales
	var normalized strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			normalized.WriteRune(r)
		case r >= '0' && r <= '9':
			normalized.WriteRune(r)
		case r == '_':
			normalized.WriteRune(r)
		// Vocales acentuadas → base
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
			// Ignorar otros caracteres
		}
	}
	name = normalized.String()

	// Verificar que no empiece con número
	if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
		name = "_" + name
	}

	// Validación final
	if !validIdentifier.MatchString(name) || name == "" {
		return ""
	}
	return name
}

// isSystemColumn retorna true si la columna es una columna del sistema.
// Estas columnas no pueden ser custom fields.
func isSystemColumn(name string) bool {
	switch name {
	case "id", "email", "email_verified", "status", "profile", "metadata",
		"disabled_at", "disabled_reason", "disabled_until",
		"created_at", "updated_at", "password_hash",
		"name", "given_name", "family_name", "picture", "locale", "language", "source_client_id":
		return true
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// Utilidades de Query Building
// ─────────────────────────────────────────────────────────────────────────────

// buildPlaceholders genera una lista de placeholders MySQL (?, ?, ?).
// count es el número de placeholders a generar.
func buildPlaceholders(count int) string {
	if count <= 0 {
		return ""
	}
	placeholders := make([]string, count)
	for i := range placeholders {
		placeholders[i] = "?"
	}
	return strings.Join(placeholders, ", ")
}

// escapeWildcard escapa caracteres wildcard para LIKE queries.
// MySQL usa % y _ como wildcards.
func escapeWildcard(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "%", "\\%")
	s = strings.ReplaceAll(s, "_", "\\_")
	return s
}

// ─────────────────────────────────────────────────────────────────────────────
// Constantes de Query
// ─────────────────────────────────────────────────────────────────────────────

// Collation para búsquedas case-insensitive
const (
	// DefaultCollation es el collation usado para strings en MySQL
	DefaultCollation = "utf8mb4_unicode_ci"
)
