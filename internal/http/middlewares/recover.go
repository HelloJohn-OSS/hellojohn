package middlewares

import (
	"net/http"

	"github.com/dropDatabas3/hellojohn/internal/http/errors"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// WithRecover captura panics y devuelve un error 500 en lugar de crashear.
func WithRecover() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					// Usar logger del contexto o singleton
					log := logger.From(r.Context())
					log.Error("panic recovered",
						logger.Op("recover"),
						logger.Any("panic", rec),
					)

					// Escribir error usando nuestro paquete de errores
					errors.WriteError(w, errors.ErrInternalServerError.WithDetail("panic recovered"))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
