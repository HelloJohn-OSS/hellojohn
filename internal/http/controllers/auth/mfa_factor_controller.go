package auth

import (
	"encoding/json"
	"net/http"
	"strings"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	"github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/auth"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"go.uber.org/zap"
)

// MFAFactorController handles factor catalog and preference endpoints.
type MFAFactorController struct {
	service svc.MFAFactorService
}

// NewMFAFactorController creates a new factor controller.
func NewMFAFactorController(s svc.MFAFactorService) *MFAFactorController {
	return &MFAFactorController{service: s}
}

// GetFactors handles GET /v2/mfa/factors.
func (c *MFAFactorController) GetFactors(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("mfa.factors.get"))

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}
	if c.service == nil {
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("mfa factors not configured"))
		return
	}

	tda := middlewares.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant required"))
		return
	}
	claims := middlewares.GetClaims(ctx)
	userID := middlewares.ClaimString(claims, "sub")
	if userID == "" {
		httperrors.WriteError(w, httperrors.ErrUnauthorized)
		return
	}

	resp, err := c.service.GetFactors(ctx, tda.Slug(), userID)
	if err != nil {
		c.handleServiceError(w, err, log)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(dto.MFAFactorsResponse{
		AvailableFactors: resp.AvailableFactors,
		PreferredFactor:  resp.PreferredFactor,
	})
}

// UpdatePreference handles PUT /v2/mfa/factors/preference.
func (c *MFAFactorController) UpdatePreference(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("mfa.factors.preference.update"))

	if r.Method != http.MethodPut {
		w.Header().Set("Allow", "PUT")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}
	if c.service == nil {
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("mfa factors not configured"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)

	tda := middlewares.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant required"))
		return
	}
	claims := middlewares.GetClaims(ctx)
	userID := middlewares.ClaimString(claims, "sub")
	if userID == "" {
		httperrors.WriteError(w, httperrors.ErrUnauthorized)
		return
	}

	var req dto.UpdateMFAFactorPreferenceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}
	req.Factor = strings.TrimSpace(req.Factor)
	if req.Factor == "" {
		httperrors.WriteError(w, httperrors.ErrMissingFields.WithDetail("factor is required"))
		return
	}

	resp, err := c.service.UpdatePreferredFactor(ctx, tda.Slug(), userID, req.Factor)
	if err != nil {
		c.handleServiceError(w, err, log)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(dto.UpdateMFAFactorPreferenceResponse{
		Updated:         resp.Updated,
		PreferredFactor: resp.PreferredFactor,
	})
}

func (c *MFAFactorController) handleServiceError(w http.ResponseWriter, err error, log *zap.Logger) {
	switch err {
	case svc.ErrMFAFactorInvalid:
		httperrors.WriteError(w, httperrors.New(http.StatusBadRequest, "invalid_mfa_factor", "Invalid MFA factor"))
	case svc.ErrMFAFactorNotAvailable:
		httperrors.WriteError(w, httperrors.New(http.StatusUnprocessableEntity, "mfa_factor_not_available", "MFA factor is not available for this user"))
	case svc.ErrMFATenantMismatch:
		httperrors.WriteError(w, httperrors.New(http.StatusUnauthorized, "invalid_client", "Tenant mismatch"))
	case svc.ErrMFAUserNotFound:
		httperrors.WriteError(w, httperrors.New(http.StatusNotFound, "user_not_found", "User not found"))
	case svc.ErrMFAStoreFailed:
		log.Error("store error", zap.Error(err))
		httperrors.WriteError(w, httperrors.New(http.StatusInternalServerError, "store_error", "Storage operation failed"))
	default:
		log.Error("unexpected error", zap.Error(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
	}
}
