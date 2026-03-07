package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	helpers "github.com/dropDatabas3/hellojohn/internal/http/helpers"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
)

// EtlController gestiona trabajos de migración ETL (data copy).
type EtlController struct {
	service svc.EtlService
}

// NewEtlController crea un EtlController.
func NewEtlController(service svc.EtlService) *EtlController {
	return &EtlController{service: service}
}

// etlStartRequest body para iniciar migración ETL.
type etlStartRequest struct {
	DSN    string `json:"dsn"`
	Driver string `json:"driver,omitempty"`
}

// StartMigration handles POST /v2/admin/tenants/{tenant_id}/etl-migrate
// Returns 202 Accepted con el job creado.
func (c *EtlController) StartMigration(w http.ResponseWriter, r *http.Request) {
	if c.service == nil {
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("ETL migration requires a global database"))
		return
	}
	tenantID := r.PathValue("tenant_id")
	if tenantID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("missing tenant_id"))
		return
	}

	var req etlStartRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}
	if req.DSN == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("dsn field is required"))
		return
	}

	job, err := c.service.StartMigration(r.Context(), tenantID, req.DSN, req.Driver)
	if err != nil {
		switch {
		case errors.Is(err, svc.ErrEtlNotAvailable):
			httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail(err.Error()))
		case errors.Is(err, svc.ErrMigrateDSNEmpty):
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("target DSN is required"))
		default:
			httperrors.WriteError(w, httperrors.ErrInternalServerError.WithCause(err))
		}
		return
	}

	helpers.WriteJSON(w, http.StatusAccepted, map[string]any{
		"job_id":     job.ID,
		"tenant_id":  job.TenantID,
		"status":     job.Status,
		"status_url": fmt.Sprintf("/v2/admin/tenants/%s/etl-migrations/%s", tenantID, job.ID),
	})
}

// ListMigrations handles GET /v2/admin/tenants/{tenant_id}/etl-migrations
func (c *EtlController) ListMigrations(w http.ResponseWriter, r *http.Request) {
	if c.service == nil {
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("ETL migration requires a global database"))
		return
	}
	tenantID := r.PathValue("tenant_id")
	if tenantID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("missing tenant_id"))
		return
	}

	jobs, err := c.service.ListJobs(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, svc.ErrEtlNotAvailable) {
			httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail(err.Error()))
			return
		}
		httperrors.WriteError(w, httperrors.ErrInternalServerError.WithCause(err))
		return
	}

	helpers.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"tenant_id": tenantID,
		"jobs":      jobs,
	})
}

// GetMigration handles GET /v2/admin/tenants/{tenant_id}/etl-migrations/{job_id}
func (c *EtlController) GetMigration(w http.ResponseWriter, r *http.Request) {
	if c.service == nil {
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("ETL migration requires a global database"))
		return
	}
	tenantID := r.PathValue("tenant_id")
	jobID := r.PathValue("job_id")
	if tenantID == "" || jobID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("missing tenant_id or job_id"))
		return
	}

	job, err := c.service.GetJobStatus(r.Context(), tenantID, jobID)
	if err != nil {
		switch {
		case errors.Is(err, svc.ErrEtlJobNotFound):
			httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("migration job not found"))
		case errors.Is(err, svc.ErrEtlNotAvailable):
			httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail(err.Error()))
		default:
			httperrors.WriteError(w, httperrors.ErrInternalServerError.WithCause(err))
		}
		return
	}

	helpers.WriteJSON(w, http.StatusOK, job)
}
