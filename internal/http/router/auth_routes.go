package router

import (
	"net/http"

	ctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/auth"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// AuthRouterDeps contiene las dependencias para el router de auth.
type AuthRouterDeps struct {
	Controllers *ctrl.Controllers
	RateLimiter mw.RateLimiter // Opcional: rate limiter por IP
	Issuer      *jwtx.Issuer   // Para endpoints que requieren auth
	DAL         store.DataAccessLayer
}

// RegisterAuthRoutes registra rutas de autenticación V2.
func RegisterAuthRoutes(mux *http.ServeMux, deps AuthRouterDeps) {
	c := deps.Controllers

	// POST /v2/auth/login
	mux.Handle("/v2/auth/login", authHandler(deps.RateLimiter, http.HandlerFunc(c.Login.Login)))

	// POST /v2/auth/register
	mux.Handle("/v2/auth/register", authHandler(deps.RateLimiter, http.HandlerFunc(c.Register.Register)))

	// POST /v2/auth/invitations/accept
	mux.Handle("/v2/auth/invitations/accept", authHandler(deps.RateLimiter, http.HandlerFunc(c.InvitationAccept.Accept)))

	// WebAuthn / Passkeys
	// POST /v2/auth/webauthn/register/begin (requires auth)
	mux.Handle("/v2/auth/webauthn/register/begin", authedHandler(deps.RateLimiter, deps.Issuer, http.HandlerFunc(c.WebAuthn.BeginRegistration)))
	// POST /v2/auth/webauthn/register/finish (requires auth)
	mux.Handle("/v2/auth/webauthn/register/finish", authedHandler(deps.RateLimiter, deps.Issuer, http.HandlerFunc(c.WebAuthn.FinishRegistration)))
	// POST /v2/auth/webauthn/login/begin
	mux.Handle("/v2/auth/webauthn/login/begin", authHandler(deps.RateLimiter, http.HandlerFunc(c.WebAuthn.BeginLogin)))
	// POST /v2/auth/webauthn/login/finish
	mux.Handle("/v2/auth/webauthn/login/finish", authHandler(deps.RateLimiter, http.HandlerFunc(c.WebAuthn.FinishLogin)))

	// POST /v2/auth/refresh
	mux.Handle("/v2/auth/refresh", authHandler(deps.RateLimiter, http.HandlerFunc(c.Refresh.Refresh)))

	// GET /v2/auth/config
	mux.Handle("/v2/auth/config", authHandler(deps.RateLimiter, http.HandlerFunc(c.Config.GetConfig)))

	// GET /v2/auth/password-policy
	mux.Handle("/v2/auth/password-policy", authHandler(deps.RateLimiter, http.HandlerFunc(c.Config.GetPasswordPolicy)))

	// GET /v2/auth/providers
	mux.Handle("/v2/auth/providers", authHandler(deps.RateLimiter, http.HandlerFunc(c.Providers.GetProviders)))

	// GET /v2/providers/status (alias compat / monitoreo) -> mismo handler que /v2/auth/providers
	mux.Handle("/v2/providers/status", authHandler(deps.RateLimiter, http.HandlerFunc(c.Providers.GetProviders)))

	// POST /v2/auth/complete-profile (requires auth)
	mux.Handle("/v2/auth/complete-profile", authedHandler(deps.RateLimiter, deps.Issuer, http.HandlerFunc(c.CompleteProfile.CompleteProfile)))

	// GET /v2/me (requires auth)
	mux.Handle("/v2/me", authedHandler(deps.RateLimiter, deps.Issuer, http.HandlerFunc(c.Me.Me)))

	// GET /v2/profile (requires auth + scope profile:read)
	mux.Handle("/v2/profile", scopedHandler(deps.RateLimiter, deps.Issuer, "profile:read", http.HandlerFunc(c.Profile.GetProfile)))

	// POST /v2/auth/logout
	mux.Handle("/v2/auth/logout", authLogoutHandler(deps.RateLimiter, deps.DAL, http.HandlerFunc(c.Logout.Logout)))

	// POST /v2/auth/logout-all
	mux.Handle("/v2/auth/logout-all", authHandler(deps.RateLimiter, http.HandlerFunc(c.Logout.LogoutAll)))

	// POST /v2/auth/magic-link/send
	mux.Handle("/v2/auth/magic-link/send", authHandler(deps.RateLimiter, http.HandlerFunc(c.Passwordless.SendMagicLink)))

	// POST /v2/auth/magic-link/verify
	mux.Handle("/v2/auth/magic-link/verify", authHandler(deps.RateLimiter, http.HandlerFunc(c.Passwordless.VerifyMagicLink)))

	// GET /v2/auth/magic-link/consume/{token}
	mux.Handle("/v2/auth/magic-link/consume/", authHandler(deps.RateLimiter, http.HandlerFunc(c.Passwordless.ConsumeMagicLink)))

	// POST /v2/auth/magic-link/exchange
	mux.Handle("/v2/auth/magic-link/exchange", authHandler(deps.RateLimiter, http.HandlerFunc(c.Passwordless.ExchangeMagicLinkCode)))

	// POST /v2/auth/otp/send
	mux.Handle("/v2/auth/otp/send", authHandler(deps.RateLimiter, http.HandlerFunc(c.Passwordless.SendOTP)))

	// POST /v2/auth/otp/verify
	mux.Handle("/v2/auth/otp/verify", authHandler(deps.RateLimiter, http.HandlerFunc(c.Passwordless.VerifyOTP)))

	// Social routes are registered in social_routes.go to avoid duplication
}

// authHandler crea el middleware chain para endpoints de auth públicos.
// Estos endpoints son especiales: tenant viene en body, no en path/header.
func authHandler(limiter mw.RateLimiter, handler http.Handler) http.Handler {
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
			KeyFunc: mw.IPPathRateKey,
		}))
	}

	// Logging al final
	chain = append(chain, mw.WithLogging())

	return mw.Chain(handler, chain...)
}

// authLogoutHandler applies CSRF protection for cookie-based logout requests.
// Bearer-based requests are still supported because WithCSRF skips Bearer auth.
func authLogoutHandler(limiter mw.RateLimiter, dal store.DataAccessLayer, handler http.Handler) http.Handler {
	chain := []mw.Middleware{
		mw.WithRecover(),
		mw.WithRequestID(),
		mw.WithSecurityHeaders(),
		mw.WithNoStore(),
		mw.WithTenantFromJSONBody(),
		mw.WithTenantResolution(dal, true),
		mw.WithCSRF(mw.CSRFConfig{}),
	}

	if limiter != nil {
		chain = append(chain, mw.WithRateLimit(mw.RateLimitConfig{
			Limiter: limiter,
			KeyFunc: mw.IPPathRateKey,
		}))
	}

	chain = append(chain, mw.WithLogging())
	return mw.Chain(handler, chain...)
}

// authedHandler crea el middleware chain para endpoints que requieren autenticación.
func authedHandler(limiter mw.RateLimiter, issuer *jwtx.Issuer, handler http.Handler) http.Handler {
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
			KeyFunc: mw.IPPathRateKey,
		}))
	}

	// Auth required
	chain = append(chain, mw.RequireAuth(issuer))

	// Logging al final
	chain = append(chain, mw.WithLogging())

	return mw.Chain(handler, chain...)
}

// scopedHandler crea el middleware chain para endpoints que requieren auth + scope específico.
func scopedHandler(limiter mw.RateLimiter, issuer *jwtx.Issuer, scope string, handler http.Handler) http.Handler {
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
			KeyFunc: mw.IPPathRateKey,
		}))
	}

	// Auth required
	chain = append(chain, mw.RequireAuth(issuer))

	// Scope required
	chain = append(chain, mw.RequireScope(scope))

	// Logging al final
	chain = append(chain, mw.WithLogging())

	return mw.Chain(handler, chain...)
}
