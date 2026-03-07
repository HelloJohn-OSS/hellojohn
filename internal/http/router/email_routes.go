package router

import (
	"net/http"

	ctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/email"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// EmailRouterDeps contiene las dependencias para el router email.
type EmailRouterDeps struct {
	Controllers *ctrl.Controllers
	DAL         store.DataAccessLayer
	RateLimiter mw.RateLimiter // Opcional: rate limiter por IP
}

// RegisterEmailRoutes registra rutas de email flows V2.
func RegisterEmailRoutes(mux *http.ServeMux, deps EmailRouterDeps) {
	c := deps.Controllers

	// POST /v2/auth/verify-email/start - Start email verification
	mux.Handle("/v2/auth/verify-email/start", emailHandler(deps, http.HandlerFunc(c.Flows.VerifyEmailStart)))

	// GET /v2/auth/verify-email - Confirm email verification
	mux.Handle("/v2/auth/verify-email", emailHandler(deps, http.HandlerFunc(c.Flows.VerifyEmailConfirm)))

	// POST /v2/auth/forgot - Initiate password reset
	mux.Handle("/v2/auth/forgot", emailHandler(deps, http.HandlerFunc(c.Flows.ForgotPassword)))

	// POST /v2/auth/reset - Complete password reset
	mux.Handle("/v2/auth/reset", emailHandler(deps, http.HandlerFunc(c.Flows.ResetPassword)))
}

// emailHandler crea el middleware chain para endpoints de email flows.
func emailHandler(deps EmailRouterDeps, handler http.Handler) http.Handler {
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

	// Tenant resolution
	if deps.DAL != nil {
		chain = append(chain,
			mw.WithTenantFromJSONBody(),              // 1. Try body if needed
			mw.WithTenantResolution(deps.DAL, false), // 2. Resolve (strict=false here, enforced later)
			mw.RequireTenant(),                       // 3. Enforce tenant present
			mw.RequireTenantDB(),                     // 4. Enforce DB available
		)
	}

	// Logging al final
	chain = append(chain, mw.WithLogging())

	return mw.Chain(handler, chain...)
}
