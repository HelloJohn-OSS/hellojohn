// Package system implementa los controllers HTTP del dominio de sistema.
package system

import (
	"encoding/json"
	"errors"
	"net/http"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	syssvc "github.com/dropDatabas3/hellojohn/internal/http/services/system"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	metrics "github.com/dropDatabas3/hellojohn/internal/metrics"
)

// StatusController maneja los endpoints /v2/system/*.
type StatusController struct {
	service syssvc.SystemService
}

// NewStatusController crea un nuevo StatusController.
func NewStatusController(svc syssvc.SystemService) *StatusController {
	return &StatusController{service: svc}
}

// GetStatus maneja GET /v2/system/status
// Retorna el estado del sistema: modo, Global DB, contadores de tenants.
func (c *StatusController) GetStatus(w http.ResponseWriter, r *http.Request) {
	result, err := c.service.GetStatus(r.Context())
	if err != nil {
		httperrors.WriteError(w, httperrors.ErrInternalServerError.WithCause(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(result) //nolint:errcheck
}

// GetHealth maneja GET /v2/system/health
// Retorna el estado agregado del cluster, Global DB y uptime.
func (c *StatusController) GetHealth(w http.ResponseWriter, r *http.Request) {
	result, err := c.service.GetHealth(r.Context())
	if err != nil {
		httperrors.WriteError(w, httperrors.ErrInternalServerError.WithCause(err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result) //nolint:errcheck
}

// RunSync maneja POST /v2/system/sync
// Ejecuta o simula (dry_run) la migración FS→DB.
func (c *StatusController) RunSync(w http.ResponseWriter, r *http.Request) {
	var req dto.SyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	result, err := c.service.RunSync(r.Context(), req)
	if err != nil {
		// Si la DB no está disponible → 503
		if errors.Is(err, store.ErrDBUnavailable) {
			httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("global DB unavailable"))
			return
		}
		// Sin Global DB configurada → 400
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(err.Error()))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result) //nolint:errcheck
}

// GetMetrics maneja GET /v2/admin/system/metrics/summary
// Retorna un snapshot de las métricas en memoria del proceso.
func (c *StatusController) GetMetrics(w http.ResponseWriter, r *http.Request) {
	result, err := c.service.GetMetrics(r.Context())
	if err != nil {
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result) //nolint:errcheck
}

// GetPrometheusMetrics maneja GET /metrics
// Retorna las métricas en formato Prometheus text exposition 0.0.4.
// Este endpoint es público — los scrapers de Prometheus no se autentican.
// La seguridad se delega al nivel de red/proxy del operador.
func (c *StatusController) GetPrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	snap, ok := c.service.MetricsSnapshot()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	metrics.WritePrometheusFormat(w, snap)
}
