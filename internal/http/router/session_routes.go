package router

import (
	"net/http"

	ctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/session"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// SessionRouterDeps contiene las dependencias para el router session.
type SessionRouterDeps struct {
	Controllers *ctrl.Controllers
	RateLimiter mw.RateLimiter        // Opcional: rate limiter por IP
	DAL         store.DataAccessLayer // DAL para tenant resolution
}

// RegisterSessionRoutes registra rutas de session V2.
func RegisterSessionRoutes(mux *http.ServeMux, deps SessionRouterDeps) {
	c := deps.Controllers

	// POST /v2/session/login - Session cookie login (requires tenant resolution)
	if c.Login != nil {
		mux.Handle("/v2/session/login", sessionLoginHandler(deps, http.HandlerFunc(c.Login.Login)))
	}

	// POST /v2/session/token - Mint short-lived JWT from active session cookie
	if c.Token != nil {
		mux.Handle("/v2/session/token", sessionTokenHandler(deps.RateLimiter, http.HandlerFunc(c.Token.Mint)))
	}
}

// sessionTokenHandler creates middleware chain for session token minting.
// CSRF is required because this endpoint relies on cookie auth.
func sessionTokenHandler(limiter mw.RateLimiter, handler http.Handler) http.Handler {
	chain := []mw.Middleware{
		mw.WithRecover(),
		mw.WithRequestID(),
		mw.WithSecurityHeaders(),
		mw.WithNoStore(),
		mw.WithCSRF(mw.CSRFConfig{}),
	}

	if limiter != nil {
		chain = append(chain, mw.WithRateLimit(mw.RateLimitConfig{
			Limiter: limiter,
			KeyFunc: mw.IPOnlyRateKey,
		}))
	}

	chain = append(chain, mw.WithLogging())
	return mw.Chain(handler, chain...)
}

// sessionLoginHandler crea el middleware chain para login que necesita tenant resolution.
func sessionLoginHandler(deps SessionRouterDeps, handler http.Handler) http.Handler {
	chain := []mw.Middleware{
		mw.WithRecover(),
		mw.WithRequestID(),
		mw.WithSecurityHeaders(),
		mw.WithNoStore(),
	}

	// Rate limiting por IP si está configurado
	if deps.RateLimiter != nil {
		chain = append(chain, mw.WithRateLimit(mw.RateLimitConfig{
			Limiter: deps.RateLimiter,
			KeyFunc: mw.IPOnlyRateKey,
		}))
	}

	// Tenant resolution for /session/login:
	// 1) peek JSON body for tenant_id/tenant and project into headers
	// 2) resolve tenant strictly (required)
	// 3) enforce tenant present in context (avoids MustGetTenant panic path)
	chain = append(chain,
		mw.WithTenantFromJSONBody(),
		mw.WithTenantResolution(deps.DAL, false),
		mw.RequireTenant(),
	)

	// Logging al final
	chain = append(chain, mw.WithLogging())

	return mw.Chain(handler, chain...)
}
