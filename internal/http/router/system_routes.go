package router

import (
	"net/http"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	sysctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/system"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
)

// SystemRouterDeps contiene las dependencias para las rutas del dominio system.
type SystemRouterDeps struct {
	Controllers *sysctrl.Controllers
	Issuer      *jwtx.Issuer
	RateLimiter mw.RateLimiter
	// APIKeyRepo enables X-API-Key authentication for system endpoints, allowing
	// remote instances to be accessed via the cloud proxy (which replaces the
	// caller's JWT with the stored API key for the target instance).
	// When nil, falls back to JWT-only authentication.
	APIKeyRepo repository.APIKeyRepository
}

// RegisterSystemRoutes registra las rutas del dominio system.
// Ambos endpoints requieren autenticación de admin (JWT admin válido).
// No son tenant-scoped (son rutas de gestión del sistema completo).
func RegisterSystemRoutes(mux *http.ServeMux, deps SystemRouterDeps) {
	if deps.Controllers == nil {
		return
	}

	mux.Handle("GET /v2/system/status", systemAdminChain(deps, deps.Controllers.Status.GetStatus))
	mux.Handle("POST /v2/system/sync", systemAdminChain(deps, deps.Controllers.Status.RunSync))
	mux.Handle("GET /v2/system/health", systemAdminChain(deps, deps.Controllers.Status.GetHealth))
	mux.Handle("GET /v2/admin/system/metrics/summary", systemAdminChain(deps, deps.Controllers.Status.GetMetrics))
	// /v2/admin/system/metrics/detailed — snapshot enriquecido para UI dashboard
	// SIEMPRE registrado porque MetricsDetailedHandler se crea incondicionalmente en NewControllers.
	// Si el collector es nil, el handler devuelve 404 desde ServeHTTP.
	mux.Handle("GET /v2/admin/system/metrics/detailed", systemAdminChain(deps, deps.Controllers.MetricsDetailed.ServeHTTP))

	// /metrics es público — necesario para scrapers Prometheus.
	// La seguridad se delega al nivel de red/proxy del operador.
	// Sin middleware de auth — correcto e intencional.
	mux.Handle("GET /metrics", systemPublicChain(deps, deps.Controllers.Status.GetPrometheusMetrics))
}

// systemPublicChain crea un handler con un middleware chain mínimo sin autenticación.
// Usado exclusivamente para endpoints que deben ser accesibles sin credenciales,
// como GET /metrics (necesario para scrapers Prometheus).
func systemPublicChain(deps SystemRouterDeps, h http.HandlerFunc) http.Handler {
	chain := []mw.Middleware{
		mw.WithRecover(),
		mw.WithRequestID(),
		mw.WithLogging(),
	}

	// Rate limiting opcional para protección básica
	if deps.RateLimiter != nil {
		chain = append(chain, mw.WithRateLimit(mw.RateLimitConfig{
			Limiter: deps.RateLimiter,
			KeyFunc: mw.IPOnlyRateKey,
		}))
	}

	return mw.Chain(h, chain...)
}

// systemAdminChain crea un handler con el middleware chain de admin de sistema.
// Sin tenant resolution (las rutas de system no están scoped a un tenant).
func systemAdminChain(deps SystemRouterDeps, h http.HandlerFunc) http.Handler {
	chain := []mw.Middleware{
		mw.WithRecover(),
		mw.WithRequestID(),
		mw.WithSecurityHeaders(),
		mw.WithNoStore(),
	}

	// Auth de admin obligatorio — acepta JWT (Bearer) y, cuando APIKeyRepo está
	// configurado, también X-API-Key. Esto permite que el cloud proxy acceda a los
	// endpoints de sistema de instancias remotas usando la API key almacenada,
	// sin exponer las credenciales JWT del operador local.
	if deps.Issuer != nil {
		chain = append(chain, mw.RequireAdminAuthOrAPIKey(deps.Issuer, deps.APIKeyRepo))
	} else {
		// Sin issuer → rechazar siempre (no exponer endpoints sin auth)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("system endpoints require JWT issuer"))
		})
	}

	// Rate limiting opcional
	if deps.RateLimiter != nil {
		chain = append(chain, mw.WithRateLimit(mw.RateLimitConfig{
			Limiter: deps.RateLimiter,
			KeyFunc: mw.IPOnlyRateKey,
		}))
	}

	chain = append(chain, mw.WithLogging())
	return mw.Chain(h, chain...)
}
