// Package router define las rutas HTTP V2 del servicio.
package router

import (
	"net/http"

	ctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/oidc"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
)

// OIDCRouterDeps contiene las dependencias para el router OIDC.
type OIDCRouterDeps struct {
	Controllers *ctrl.Controllers
	Issuer      *jwtx.Issuer   // Para RequireAuth en /userinfo
	RateLimiter mw.RateLimiter // Opcional: rate limiter por IP para /userinfo
}

// RegisterOIDCRoutes registra rutas OIDC/Discovery públicas.
func RegisterOIDCRoutes(mux *http.ServeMux, deps OIDCRouterDeps) {
	c := deps.Controllers

	// JWKS Global: /.well-known/jwks.json (público)
	mux.Handle("/.well-known/jwks.json", oidcPublicHandler(http.HandlerFunc(c.JWKS.GetGlobal)))

	// JWKS por Tenant: /.well-known/jwks/{slug}.json (público)
	mux.Handle("/.well-known/jwks/", oidcPublicHandler(http.HandlerFunc(c.JWKS.GetByTenant)))

	// OIDC Discovery Global: /.well-known/openid-configuration (público)
	mux.Handle("/.well-known/openid-configuration", oidcPublicHandler(http.HandlerFunc(c.Discovery.GetGlobal)))

	// OIDC Discovery por Tenant: /t/{slug}/.well-known/openid-configuration (público)
	mux.Handle("/t/", oidcPublicHandler(http.HandlerFunc(c.Discovery.GetByTenant)))

	// OIDC UserInfo: GET/POST /userinfo (requiere Bearer token)
	mux.Handle("/userinfo", oidcUserInfoHandler(deps.Issuer, deps.RateLimiter, http.HandlerFunc(c.UserInfo.GetUserInfo)))
}

// oidcPublicHandler crea el middleware chain para endpoints OIDC públicos.
func oidcPublicHandler(handler http.Handler) http.Handler {
	return mw.Chain(handler,
		mw.WithRecover(),
		mw.WithRequestID(),
		mw.WithLogging(),
	)
}

// oidcUserInfoHandler crea el middleware chain para /userinfo.
// Requiere auth pero no tenant resolution (tenant viene del token).
func oidcUserInfoHandler(issuer *jwtx.Issuer, limiter mw.RateLimiter, handler http.Handler) http.Handler {
	chain := []mw.Middleware{
		mw.WithRecover(),
		mw.WithRequestID(),
		mw.RequireAuth(issuer), // Valida token JWT
		mw.RequireUser(),       // Requiere sub en claims
		mw.WithNoStore(),
	}

	// Rate limiting opcional por IP
	if limiter != nil {
		chain = append(chain, mw.WithRateLimit(mw.RateLimitConfig{
			Limiter: limiter,
			KeyFunc: mw.IPOnlyRateKey,
		}))
	}

	chain = append(chain, mw.WithLogging())

	return mw.Chain(handler, chain...)
}
