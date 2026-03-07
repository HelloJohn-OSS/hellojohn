package router

import (
	"net/http"

	ctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/oauth"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
)

// OAuthRouterDeps contiene las dependencias para el router OAuth.
type OAuthRouterDeps struct {
	Controllers *ctrl.Controllers
	RateLimiter mw.RateLimiter // Opcional: rate limiter por IP
}

// RegisterOAuthRoutes registra rutas OAuth2/OIDC V2.
func RegisterOAuthRoutes(mux *http.ServeMux, deps OAuthRouterDeps) {
	c := deps.Controllers

	// GET /oauth2/authorize - Authorization endpoint (OAuth 2.1 / OIDC)
	mux.Handle("/oauth2/authorize", oauthHandler(deps.RateLimiter, http.HandlerFunc(c.Authorize.Authorize)))

	// POST /oauth2/token - Token endpoint (RFC 6749)
	mux.Handle("/oauth2/token", oauthHandler(deps.RateLimiter, http.HandlerFunc(c.Token.Token)))

	// POST /oauth2/revoke - Token revocation (RFC 7009)
	mux.Handle("/oauth2/revoke", oauthHandler(deps.RateLimiter, http.HandlerFunc(c.Revoke.Revoke)))

	// POST /oauth2/introspect - Token introspection (RFC 7662)
	mux.Handle("/oauth2/introspect", oauthHandler(deps.RateLimiter, http.HandlerFunc(c.Introspect.Introspect)))

	// GET /v2/auth/consent/info - Get consent info with scope DisplayNames (ISS-05-03)
	mux.Handle("/v2/auth/consent/info", oauthHandler(deps.RateLimiter, http.HandlerFunc(c.Consent.GetInfo)))

	// POST /v2/auth/consent/accept - Consent Accept (SPA)
	mux.Handle("/v2/auth/consent/accept", oauthHandler(deps.RateLimiter, http.HandlerFunc(c.Consent.Accept)))
}

// oauthHandler crea el middleware chain para endpoints OAuth.
func oauthHandler(limiter mw.RateLimiter, handler http.Handler) http.Handler {
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
