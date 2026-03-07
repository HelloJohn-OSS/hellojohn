package admin

import (
	"encoding/json"
	"net/http"
	"strings"

	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// MFAStatusController handles GET /v2/admin/tenants/{tenant_id}/mfa/status.
type MFAStatusController struct {
	service svc.MFAStatusService
}

// NewMFAStatusController builds an MFAStatusController.
func NewMFAStatusController(service svc.MFAStatusService) *MFAStatusController {
	return &MFAStatusController{service: service}
}

// GetStatus returns tenant MFA status for admin sessions.
func (c *MFAStatusController) GetStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("MFAStatusController.GetStatus"))

	tenantID := strings.TrimSpace(r.PathValue("tenant_id"))
	if tenantID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant_id is required"))
		return
	}

	status, err := c.service.GetStatus(ctx, tenantID)
	if err != nil {
		log.Error("get mfa status failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}
