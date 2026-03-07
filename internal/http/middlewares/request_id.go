package middlewares

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

// WithRequestID genera o propaga un Request ID único para cada request.
// Si el cliente envía X-Request-ID, lo usa. Si no, genera uno nuevo.
// El ID se expone en el header de respuesta y se inyecta en el contexto.
func WithRequestID() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rid := strings.TrimSpace(r.Header.Get("X-Request-ID"))
			if rid == "" {
				var b [16]byte
				_, _ = rand.Read(b[:])
				rid = hex.EncodeToString(b[:])
			}

			// Exponer en response header
			w.Header().Set("X-Request-ID", rid)

			// Inyectar en contexto para uso en logs/handlers
			ctx := setRequestID(r.Context(), rid)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
