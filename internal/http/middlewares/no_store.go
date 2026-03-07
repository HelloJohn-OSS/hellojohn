package middlewares

import "net/http"

// WithNoStore agrega Cache-Control: no-store a la respuesta.
// Útil para endpoints sensibles como JWKS, discovery, etc.
func WithNoStore() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			next.ServeHTTP(w, r)
		})
	}
}

// WithCacheControl agrega Cache-Control con TTL configurable.
func WithCacheControl(directive string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", directive)
			next.ServeHTTP(w, r)
		})
	}
}
