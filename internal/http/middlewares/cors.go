package middlewares

import (
	"net/http"
	"strings"
)

// WithCORS crea un middleware que maneja CORS para los orígenes permitidos.
// Soporta "*" para permitir cualquier origen.
func WithCORS(allowed []string) Middleware {
	trim := func(s string) string { return strings.TrimRight(strings.TrimSpace(s), "/") }

	alist := make([]string, len(allowed))
	for i, v := range allowed {
		alist[i] = trim(v)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := trim(r.Header.Get("Origin"))
			allowedOrigin := ""

			for _, a := range alist {
				if a == "*" || (origin != "" && strings.EqualFold(origin, a)) {
					allowedOrigin = origin
					break
				}
			}

			// Vary headers para caches/proxies
			w.Header().Add("Vary", "Origin")
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.Header().Add("Vary", "Access-Control-Request-Headers")

			if allowedOrigin != "" {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", allowedOrigin)
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,HEAD,OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Cache-Control, Pragma, X-Request-ID, If-Match, X-Tenant-ID, X-Tenant-Slug, X-CSRF-Token")
				h.Set("Access-Control-Expose-Headers", "ETag, X-Request-ID, X-RateLimit-Remaining, X-RateLimit-Limit, X-RateLimit-Reset, Retry-After, WWW-Authenticate, Location")
				h.Set("Access-Control-Max-Age", "600") // preflight cache 10 min
			}

			// Preflight request
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
