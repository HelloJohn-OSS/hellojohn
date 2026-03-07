// Package health contiene el controller para health checks.
package health

import (
	"encoding/json"
	"net/http"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/health"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/health"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// HealthController maneja las rutas de health check.
type HealthController struct {
	service svc.HealthService
}

// NewHealthController crea un nuevo controller de health check.
func NewHealthController(service svc.HealthService) *HealthController {
	return &HealthController{service: service}
}

// Readyz maneja GET /readyz
func (c *HealthController) Readyz(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("HealthController.Readyz"))

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	response := c.service.Check(ctx)

	// Headers para compatibilidad
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if response.Version != "" {
		w.Header().Set("X-Service-Version", response.Version)
	}
	if response.Commit != "" {
		w.Header().Set("X-Service-Commit", response.Commit)
	}
	if response.ActiveKeyID != "" {
		w.Header().Set("X-JWKS-KID", response.ActiveKeyID)
	}

	// Status code según estado
	var statusCode int
	switch response.Status {
	case "unavailable":
		statusCode = http.StatusServiceUnavailable
	default: // "ready" o "degraded"
		statusCode = http.StatusOK
	}

	log.Debug("health check completed",
		logger.String("status", response.Status),
		logger.Int("components_count", len(response.Components)),
	)

	writeJSON(w, statusCode, response)
}

func writeJSON(w http.ResponseWriter, status int, v dto.HealthResponse) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
