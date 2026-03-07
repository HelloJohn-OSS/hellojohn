package router

import (
	"net/http"

	ctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/social"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
)

// SocialRouterDeps contiene las dependencias para el router social.
type SocialRouterDeps struct {
	Controllers *ctrl.Controllers
	RateLimiter mw.RateLimiter // Opcional: rate limiter por IP
}

// RegisterSocialRoutes registra rutas de social login V2.
func RegisterSocialRoutes(mux *http.ServeMux, deps SocialRouterDeps) {
	c := deps.Controllers

	// POST /v2/auth/social/exchange - Exchange social login code for tokens
	mux.Handle("/v2/auth/social/exchange", socialHandler(deps.RateLimiter, http.HandlerFunc(c.Exchange.Exchange)))

	// GET /v2/auth/social/result - View social login code result (debug/viewer)
	mux.Handle("/v2/auth/social/result", socialHandler(deps.RateLimiter, http.HandlerFunc(c.Result.GetResult)))

	// GET /v2/auth/social/{provider}/start - Start social login flow (Go 1.22+ path params)
	mux.Handle("GET /v2/auth/social/{provider}/start", socialHandler(deps.RateLimiter, http.HandlerFunc(c.Start.Start)))

	// GET /v2/auth/social/{provider}/callback - OAuth callback (Go 1.22+ path params)
	mux.Handle("GET /v2/auth/social/{provider}/callback", socialHandler(deps.RateLimiter, http.HandlerFunc(c.Callback.Callback)))
	// POST /v2/auth/social/{provider}/callback - Apple form_post callback compatibility
	mux.Handle("POST /v2/auth/social/{provider}/callback", socialHandler(deps.RateLimiter, http.HandlerFunc(c.Callback.Callback)))
}

// socialHandler crea el middleware chain para endpoints de social login.
func socialHandler(limiter mw.RateLimiter, handler http.Handler) http.Handler {
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
