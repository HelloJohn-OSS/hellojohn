package middlewares

import (
	"net/http"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/http/errors"
)

// CSRFConfig configura el middleware CSRF.
type CSRFConfig struct {
	HeaderName string // Default: "X-CSRF-Token"
	CookieName string // Default: "csrf_token"
}

// WithCSRF enforces double-submit CSRF check for cookie-based requests.
// Comportamiento:
//   - Si Authorization: Bearer está presente, el check se salta (no es flujo de cookies).
//   - Para métodos inseguros (POST, PUT, PATCH, DELETE), requiere header y cookie con mismo valor.
func WithCSRF(cfg CSRFConfig) Middleware {
	headerName := strings.TrimSpace(cfg.HeaderName)
	if headerName == "" {
		headerName = "X-CSRF-Token"
	}
	cookieName := strings.TrimSpace(cfg.CookieName)
	if cookieName == "" {
		cookieName = "csrf_token"
	}

	isUnsafe := func(m string) bool {
		switch strings.ToUpper(m) {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			return true
		default:
			return false
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isUnsafe(r.Method) {
				next.ServeHTTP(w, r)
				return
			}

			// Skip CSRF if Bearer auth is present (not a cookie flow)
			if ah := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(ah), "bearer ") {
				next.ServeHTTP(w, r)
				return
			}

			// Read header and cookie
			hdr := strings.TrimSpace(r.Header.Get(headerName))
			ck, _ := r.Cookie(cookieName)

			if hdr == "" || ck == nil || strings.TrimSpace(ck.Value) == "" {
				errors.WriteError(w, errors.ErrCSRFTokenMissing)
				return
			}

			if !constantTimeEqual(hdr, ck.Value) {
				errors.WriteError(w, errors.ErrCSRFTokenInvalid)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// constantTimeEqual compara dos strings en tiempo constante para evitar timing attacks.
func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
