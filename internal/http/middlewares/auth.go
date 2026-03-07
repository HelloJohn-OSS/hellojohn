package middlewares

import (
	"net/http"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/http/errors"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
)

// =================================================================================
// AUTHENTICATION MIDDLEWARES
// =================================================================================

// RequireAuth valida Authorization: Bearer <JWT> y guarda las claims en el contexto.
// Si el token es inválido o no está presente, responde 401.
func RequireAuth(issuer *jwtx.Issuer) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ah := strings.TrimSpace(r.Header.Get("Authorization"))
			if ah == "" || !strings.HasPrefix(strings.ToLower(ah), "bearer ") {
				w.Header().Set("WWW-Authenticate", `Bearer realm="api", error="invalid_token", error_description="missing bearer token"`)
				errors.WriteError(w, errors.ErrTokenMissing)
				return
			}
			raw := strings.TrimSpace(ah[len("Bearer "):])

			claims, err := jwtx.ParseEdDSA(raw, issuer, "")
			if err != nil {
				w.Header().Set("WWW-Authenticate", `Bearer realm="api", error="invalid_token", error_description="`+err.Error()+`"`)
				errors.WriteError(w, errors.ErrTokenInvalid.WithDetail(err.Error()))
				return
			}

			if !isAcceptedBearerClaims(claims) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="api", error="invalid_token", error_description="unsupported token type"`)
				errors.WriteError(w, errors.ErrTokenInvalid.WithDetail("unsupported token type"))
				return
			}

			// Inyectar claims en contexto
			ctx := WithClaims(r.Context(), claims)

			// También extraer y guardar el user ID si está presente
			if sub := ClaimString(claims, "sub"); sub != "" {
				ctx = WithUserID(ctx, sub)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalAuth intenta validar el token JWT pero NO falla si no está presente.
// Útil para endpoints que tienen comportamiento diferente para usuarios autenticados.
func OptionalAuth(issuer *jwtx.Issuer) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ah := strings.TrimSpace(r.Header.Get("Authorization"))
			if ah == "" || !strings.HasPrefix(strings.ToLower(ah), "bearer ") {
				// No hay token, continuar sin claims
				next.ServeHTTP(w, r)
				return
			}
			raw := strings.TrimSpace(ah[len("Bearer "):])

			claims, err := jwtx.ParseEdDSA(raw, issuer, "")
			if err != nil {
				// Token inválido pero opcional, continuar sin claims
				next.ServeHTTP(w, r)
				return
			}

			// Inyectar claims en contexto
			ctx := WithClaims(r.Context(), claims)
			if sub := ClaimString(claims, "sub"); sub != "" {
				ctx = WithUserID(ctx, sub)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireUser verifica que haya un usuario autenticado en el contexto.
// Debe usarse después de RequireAuth.
func RequireUser() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if GetUserID(r.Context()) == "" {
				errors.WriteError(w, errors.ErrUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isAcceptedBearerClaims(claims map[string]any) bool {
	// Never accept refresh tokens as bearer access tokens.
	if tu, ok := claims["token_use"].(string); ok && strings.EqualFold(strings.TrimSpace(tu), "refresh") {
		return false
	}

	// typ claim is optional; when present, enforce allowlist.
	typ, _ := claims["typ"].(string)
	typ = strings.ToLower(strings.TrimSpace(typ))
	if typ == "" {
		return true
	}

	switch typ {
	case "access_token", "session_token":
		return true
	default:
		return false
	}
}
