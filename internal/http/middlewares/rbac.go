package middlewares

import (
	"net/http"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/claims"
	"github.com/dropDatabas3/hellojohn/internal/http/errors"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
)

// =================================================================================
// RBAC MIDDLEWARES
// =================================================================================

// hasAny verifica si hay al menos un elemento en común entre dos slices.
func hasAny(haystack []string, needles []string) bool {
	if len(haystack) == 0 || len(needles) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(haystack))
	for _, v := range haystack {
		set[strings.ToLower(strings.TrimSpace(v))] = struct{}{}
	}
	for _, n := range needles {
		if _, ok := set[strings.ToLower(strings.TrimSpace(n))]; ok {
			return true
		}
	}
	return false
}

// extractRolesFromClaims extrae roles del namespace del sistema dentro de las claims.
func extractRolesFromClaims(cl map[string]any, sysNS string) []string {
	sysMap := ClaimMap(cl, sysNS)
	if sysMap == nil {
		return nil
	}
	return ClaimStringSlice(sysMap, "roles")
}

// extractPermsFromClaims extrae permisos del namespace del sistema.
func extractPermsFromClaims(cl map[string]any, sysNS string) []string {
	sysMap := ClaimMap(cl, sysNS)
	if sysMap == nil {
		return nil
	}
	return ClaimStringSlice(sysMap, "perms")
}

// RequireRole verifica que el usuario tenga al menos uno de los roles especificados.
// Los roles se buscan en custom[sysNS].roles.
func RequireRole(issuer *jwtx.Issuer, roles ...string) Middleware {
	sysNS := claims.SystemNamespace(issuer.Iss)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cl := GetClaims(r.Context())
			if cl == nil {
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				errors.WriteError(w, errors.ErrUnauthorized.WithDetail("token invalid or missing"))
				return
			}

			have := extractRolesFromClaims(cl, sysNS)
			if !hasAny(have, roles) {
				errors.WriteError(w, errors.ErrForbidden.WithDetail("insufficient role"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole es alias de RequireRole para claridad semántica.
var RequireAnyRole = RequireRole

// RequireAllRoles verifica que el usuario tenga TODOS los roles especificados.
func RequireAllRoles(issuer *jwtx.Issuer, roles ...string) Middleware {
	sysNS := claims.SystemNamespace(issuer.Iss)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cl := GetClaims(r.Context())
			if cl == nil {
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				errors.WriteError(w, errors.ErrUnauthorized.WithDetail("token invalid or missing"))
				return
			}

			have := extractRolesFromClaims(cl, sysNS)
			haveSet := make(map[string]struct{}, len(have))
			for _, r := range have {
				haveSet[strings.ToLower(strings.TrimSpace(r))] = struct{}{}
			}

			for _, needed := range roles {
				if _, ok := haveSet[strings.ToLower(strings.TrimSpace(needed))]; !ok {
					errors.WriteError(w, errors.ErrForbidden.WithDetail("missing role: "+needed))
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePerm verifica que el usuario tenga al menos uno de los permisos especificados.
// Los permisos se buscan en custom[sysNS].perms.
func RequirePerm(issuer *jwtx.Issuer, perms ...string) Middleware {
	sysNS := claims.SystemNamespace(issuer.Iss)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cl := GetClaims(r.Context())
			if cl == nil {
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				errors.WriteError(w, errors.ErrUnauthorized.WithDetail("token invalid or missing"))
				return
			}

			have := extractPermsFromClaims(cl, sysNS)
			if !hasAny(have, perms) {
				errors.WriteError(w, errors.ErrForbidden.WithDetail("insufficient permission"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyPerm es alias de RequirePerm para claridad semántica.
var RequireAnyPerm = RequirePerm
