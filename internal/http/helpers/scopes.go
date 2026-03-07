// Package helpers contiene funciones auxiliares compartidas para HTTP V2.
// Estas funciones se reusan en controllers y services para evitar duplicación.
package helpers

import (
	"strings"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// ─────────────────────────────────────────────────────────────────────────────
// SCOPES HELPERS
// ─────────────────────────────────────────────────────────────────────────────

// ExtractScopes extrae los scopes de claims JWT.
// Soporta múltiples formatos:
//   - "scp" como []any (array de strings)
//   - "scp" como string (space-separated)
//   - "scope" como string (space-separated)
func ExtractScopes(claims map[string]any) []string {
	// scp como []any
	if v, ok := claims["scp"].([]any); ok {
		scopes := make([]string, 0, len(v))
		for _, i := range v {
			if s, ok := i.(string); ok {
				scopes = append(scopes, s)
			}
		}
		return scopes
	}

	// scp como string (space-separated)
	if v, ok := claims["scp"].(string); ok {
		return strings.Fields(v)
	}

	// scope como string (space-separated)
	if v, ok := claims["scope"].(string); ok {
		return strings.Fields(v)
	}

	return nil
}

// ExtractScopesFromMapClaims es una variante tipada para jwtv5.MapClaims.
func ExtractScopesFromMapClaims(claims jwtv5.MapClaims) []string {
	return ExtractScopes(claims)
}

// HasScope verifica si un scope específico está presente en la lista.
// La comparación es case-insensitive.
func HasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}
