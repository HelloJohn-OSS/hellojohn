package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

const maxImportBodySize = 50 * 1024 * 1024 // 50 MB

// ImportController maneja endpoints de bulk import de usuarios.
type ImportController struct {
	service svc.ImportService
}

// NewImportController construye un ImportController.
func NewImportController(service svc.ImportService) *ImportController {
	return &ImportController{service: service}
}

// StartImport maneja POST /v2/admin/tenants/{tenant_id}/users/import.
func (c *ImportController) StartImport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ImportController.StartImport"))

	tenantID := strings.TrimSpace(r.PathValue("tenant_id"))
	if tenantID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant_id is required"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxImportBodySize)

	jobID, err := c.service.StartImport(ctx, tenantID, r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			httperrors.WriteError(w, httperrors.ErrBodyTooLarge.WithDetail("file too large; max 50MB"))
			return
		}
		log.Error("start import failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(dto.StartUserImportResponse{
		JobID:  jobID,
		Status: "processing",
	})
}

// GetImportStatus maneja GET /v2/admin/tenants/{tenant_id}/users/import/{job_id}.
func (c *ImportController) GetImportStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ImportController.GetImportStatus"))

	jobID := strings.TrimSpace(r.PathValue("job_id"))
	if jobID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("job_id is required"))
		return
	}

	status, err := c.service.GetImportStatus(ctx, jobID)
	if err != nil {
		if errors.Is(err, svc.ErrImportJobNotFound) {
			httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("import job not found"))
			return
		}
		log.Error("get import status failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}
