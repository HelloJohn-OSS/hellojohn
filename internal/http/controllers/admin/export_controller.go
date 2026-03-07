package admin

import (
	"net/http"
	"strings"

	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// ExportController maneja endpoint de export de usuarios.
type ExportController struct {
	service svc.ExportService
}

// NewExportController construye un ExportController.
func NewExportController(service svc.ExportService) *ExportController {
	return &ExportController{service: service}
}

// ExportUsers maneja GET /v2/admin/tenants/{tenant_id}/users/export.
func (c *ExportController) ExportUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ExportController.ExportUsers"))

	tenantID := strings.TrimSpace(r.PathValue("tenant_id"))
	if tenantID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant_id is required"))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="users_export.json"`)
	w.WriteHeader(http.StatusOK)

	if err := c.service.ExportUsers(ctx, tenantID, w); err != nil {
		log.Error("export users failed", logger.Err(err))
	}
}
