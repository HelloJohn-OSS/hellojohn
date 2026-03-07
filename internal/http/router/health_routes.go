package router

import (
	"net/http"

	ctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/health"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
)

// HealthRouterDeps contiene las dependencias para el router de health.
type HealthRouterDeps struct {
	Controllers *ctrl.Controllers
}

// RegisterHealthRoutes registra rutas de health check.
// /readyz es público, no requiere auth.
func RegisterHealthRoutes(mux *http.ServeMux, deps HealthRouterDeps) {
	c := deps.Controllers

	// GET /readyz - health check público
	mux.Handle("/readyz", healthBaseHandler(http.HandlerFunc(c.Health.Readyz)))
}

// healthBaseHandler crea el middleware chain base para endpoints de health.
// Sin auth, sin tenant, solo infra básica.
func healthBaseHandler(handler http.Handler) http.Handler {
	return mw.Chain(handler,
		mw.WithRecover(),
		mw.WithRequestID(),
		// No logging para health checks (muy frecuentes)
	)
}
