package auth

import (
	"encoding/json"
	"net/http"
	"strings"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/auth"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"go.uber.org/zap"
)

// ConfigController handles GET /v2/auth/config.
type ConfigController struct {
	service svc.ConfigService
}

// NewConfigController creates a new config controller.
func NewConfigController(service svc.ConfigService) *ConfigController {
	return &ConfigController{service: service}
}

// GetConfig handles the auth config request.
// GET /v2/auth/config?client_id=...
func (c *ConfigController) GetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ConfigController.GetConfig"))

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	clientID := r.URL.Query().Get("client_id")

	result, err := c.service.GetConfig(ctx, clientID)
	if err != nil {
		c.handleError(w, err, log)
		return
	}

	// Build response
	resp := dto.ConfigResponse{
		TenantName:               result.TenantName,
		TenantSlug:               result.TenantSlug,
		ClientName:               result.ClientName,
		LogoURL:                  result.LogoURL,
		PrimaryColor:             result.PrimaryColor,
		SocialProviders:          result.SocialProviders,
		PasswordEnabled:          result.PasswordEnabled,
		Features:                 result.Features,
		CustomFields:             result.CustomFields,
		RequireEmailVerification: result.RequireEmailVerification,
		ResetPasswordURL:         result.ResetPasswordURL,
		VerifyEmailURL:           result.VerifyEmailURL,
		BotProtection:            result.BotProtection,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)

	log.Debug("config returned", logger.TenantSlug(result.TenantSlug))
}

// GetPasswordPolicy handles:
// GET /v2/auth/password-policy?tenant_id={slug_or_id}
func (c *ConfigController) GetPasswordPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ConfigController.GetPasswordPolicy"))

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
	result, err := c.service.GetPasswordPolicy(ctx, tenantID)
	if err != nil {
		c.handleError(w, err, log)
		return
	}

	resp := dto.PasswordPolicyResponse{
		Configured:       result.Configured,
		TenantID:         result.TenantID,
		MinLength:        result.MinLength,
		MaxLength:        result.MaxLength,
		RequireUppercase: result.RequireUppercase,
		RequireLowercase: result.RequireLowercase,
		RequireNumbers:   result.RequireNumbers,
		RequireSymbols:   result.RequireSymbols,
		MaxHistory:       result.MaxHistory,
		BreachDetection:  result.BreachDetection,
		CommonPassword:   result.CommonPassword,
		PersonalInfo:     result.PersonalInfo,
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// handleError maps service errors to HTTP responses.
func (c *ConfigController) handleError(w http.ResponseWriter, err error, log *zap.Logger) {
	switch err {
	case svc.ErrConfigClientNotFound:
		httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("client not found"))
	case svc.ErrConfigTenantNotFound:
		httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("tenant not found"))
	default:
		log.Error("unexpected config error", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
	}
}
