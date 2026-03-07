package admin

import (
	"encoding/json"
	"net/http"
	"strings"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// MFAConfigController handles tenant MFA config endpoints.
type MFAConfigController struct {
	service svc.MFAConfigService
}

// NewMFAConfigController creates a new MFAConfigController.
func NewMFAConfigController(service svc.MFAConfigService) *MFAConfigController {
	return &MFAConfigController{service: service}
}

// GetConfig handles GET /v2/admin/tenants/{tenant_id}/mfa/config.
func (c *MFAConfigController) GetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("MFAConfigController.GetConfig"))

	tenantID := strings.TrimSpace(r.PathValue("tenant_id"))
	if tenantID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant_id is required"))
		return
	}

	cfg, err := c.service.GetConfig(ctx, tenantID)
	if err != nil {
		log.Error("get mfa config failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cfg)
}

// UpdateConfig handles PUT /v2/admin/tenants/{tenant_id}/mfa/config.
func (c *MFAConfigController) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("MFAConfigController.UpdateConfig"))

	tenantID := strings.TrimSpace(r.PathValue("tenant_id"))
	if tenantID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant_id is required"))
		return
	}

	var req dto.UpdateMFAConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	cfg, err := c.service.UpdateConfig(ctx, tenantID, req)
	if err != nil {
		log.Error("update mfa config failed", logger.Err(err))
		httperrors.WriteError(w, mapTenantError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cfg)
}
