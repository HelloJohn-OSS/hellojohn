package router

import (
	"net/http"

	ctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/security"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
)

// SecurityRouterDeps contiene las dependencias para el router security.
type SecurityRouterDeps struct {
	Controllers *ctrl.Controllers
	RateLimiter mw.RateLimiter // Opcional: rate limiter por IP
}

// RegisterSecurityRoutes registra rutas de security V2.
func RegisterSecurityRoutes(mux *http.ServeMux, deps SecurityRouterDeps) {
	c := deps.Controllers

	// GET /v2/csrf - CSRF token generation (double-submit pattern)
	mux.Handle("/v2/csrf", securityHandler(deps.RateLimiter, http.HandlerFunc(c.CSRF.GetToken)))
}

// securityHandler crea el middleware chain para endpoints de security.
func securityHandler(limiter mw.RateLimiter, handler http.Handler) http.Handler {
	chain := []mw.Middleware{
		mw.WithRecover(),
		mw.WithRequestID(),
		mw.WithSecurityHeaders(),
		mw.WithNoStore(),
	}

	// Rate limiting por IP si está configurado
	if limiter != nil {
		chain = append(chain, mw.WithRateLimit(mw.RateLimitConfig{
			Limiter: limiter,
			KeyFunc: mw.IPOnlyRateKey,
		}))
	}

	// Logging al final
	chain = append(chain, mw.WithLogging())

	return mw.Chain(handler, chain...)
}
