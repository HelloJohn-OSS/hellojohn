package middlewares

import (
	"net/http"
	"strings"
)

// isHTTPS detecta si el request llegó por HTTPS (directo o detrás de proxy).
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return false
}

// WithSecurityHeaders inyecta cabeceras de seguridad por defecto.
// Diseñado para APIs, no para páginas HTML.
func WithSecurityHeaders() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()

			// Referrer y MIME sniffing
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("X-Content-Type-Options", "nosniff")

			// DNS prefetch y cross-domain policies
			h.Set("X-DNS-Prefetch-Control", "off")
			h.Set("X-Permitted-Cross-Domain-Policies", "none")
			h.Set("Cross-Origin-Resource-Policy", "same-site")

			// Clickjacking
			h.Set("X-Frame-Options", "DENY")

			// CSP estricta para API (no servimos HTML)
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

			// Permissions-Policy: deshabilitar superficies no usadas por una API
			h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")

			// HSTS si HTTPS
			if isHTTPS(r) {
				h.Set("Strict-Transport-Security", "max-age=15552000; includeSubDomains")
			}

			next.ServeHTTP(w, r)
		})
	}
}
