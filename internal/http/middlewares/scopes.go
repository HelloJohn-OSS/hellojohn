package middlewares

import (
	"net/http"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/http/errors"
	"github.com/dropDatabas3/hellojohn/internal/http/helpers"
)

// =================================================================================
// SCOPE MIDDLEWARES
// =================================================================================

// extractScopes usa el helper centralizado para extraer scopes.
func extractScopes(cl map[string]any) []string {
	return helpers.ExtractScopes(cl)
}

// hasScope usa el helper centralizado para verificar scope.
func hasScope(scopes []string, want string) bool {
	return helpers.HasScope(scopes, want)
}

// RequireScope verifica que el access token contenga el scope requerido.
// Debe usarse después de RequireAuth.
func RequireScope(scope string) Middleware {
	scope = strings.ToLower(strings.TrimSpace(scope))

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if scope == "" {
				next.ServeHTTP(w, r)
				return
			}

			cl := GetClaims(r.Context())
			if cl == nil {
				errors.WriteError(w, errors.ErrUnauthorized.WithDetail("no claims in context"))
				return
			}

			scopes := extractScopes(cl)
			if !hasScope(scopes, scope) {
				w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+scope+`"`)
				errors.WriteError(w, errors.ErrInsufficientScopes.WithDetail("required scope: "+scope))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyScope verifica que el access token contenga AL MENOS UNO de los scopes.
func RequireAnyScope(scopes ...string) Middleware {
	var need []string
	for _, s := range scopes {
		if n := strings.ToLower(strings.TrimSpace(s)); n != "" {
			need = append(need, n)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(need) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			cl := GetClaims(r.Context())
			if cl == nil {
				errors.WriteError(w, errors.ErrUnauthorized.WithDetail("no claims in context"))
				return
			}

			have := extractScopes(cl)
			found := false
			for _, n := range need {
				if hasScope(have, n) {
					found = true
					break
				}
			}

			if !found {
				w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+strings.Join(need, " ")+`"`)
				errors.WriteError(w, errors.ErrInsufficientScopes.WithDetail("required scope (any of): "+strings.Join(need, ", ")))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAllScopes verifica que el access token contenga TODOS los scopes.
func RequireAllScopes(scopes ...string) Middleware {
	var need []string
	for _, s := range scopes {
		if n := strings.ToLower(strings.TrimSpace(s)); n != "" {
			need = append(need, n)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(need) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			cl := GetClaims(r.Context())
			if cl == nil {
				errors.WriteError(w, errors.ErrUnauthorized.WithDetail("no claims in context"))
				return
			}

			have := extractScopes(cl)
			for _, n := range need {
				if !hasScope(have, n) {
					w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+n+`"`)
					errors.WriteError(w, errors.ErrInsufficientScopes.WithDetail("missing scope: "+n))
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
