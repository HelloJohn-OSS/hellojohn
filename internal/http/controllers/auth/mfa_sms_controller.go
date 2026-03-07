package auth

import (
	"encoding/json"
	"net/http"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	"github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/auth"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"go.uber.org/zap"
)

// MFASMSController handles SMS MFA endpoints.
type MFASMSController struct {
	service svc.MFASMSService
}

// NewMFASMSController creates a new SMS MFA controller.
func NewMFASMSController(s svc.MFASMSService) *MFASMSController {
	return &MFASMSController{service: s}
}

// Send handles POST /v2/mfa/sms/send.
func (c *MFASMSController) Send(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("mfa.sms.send"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}
	if c.service == nil {
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("sms mfa not configured"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)

	tda := middlewares.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant required"))
		return
	}
	tenantSlug := tda.Slug()

	var req dto.SendSMSRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	resp, err := c.service.Send(ctx, tenantSlug, svc.SendSMSRequest{
		MFAToken: req.MFAToken,
	})
	if err != nil {
		c.handleServiceError(w, err, log)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(dto.SendSMSResponse{
		Sent:      resp.Sent,
		ExpiresIn: resp.ExpiresIn,
	})
}

// Challenge handles POST /v2/mfa/sms/challenge.
func (c *MFASMSController) Challenge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("mfa.sms.challenge"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}
	if c.service == nil {
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("sms mfa not configured"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)

	tda := middlewares.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant required"))
		return
	}
	tenantSlug := tda.Slug()

	var req dto.ChallengeSMSRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	resp, err := c.service.Challenge(ctx, tenantSlug, svc.ChallengeSMSRequest{
		MFAToken:       req.MFAToken,
		Code:           req.Code,
		RememberDevice: req.RememberDevice,
	})
	if err != nil {
		c.handleServiceError(w, err, log)
		return
	}

	if resp.DeviceToken != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "__Host-hj-trusted",
			Value:    resp.DeviceToken,
			Path:     "/",
			MaxAge:   30 * 24 * 60 * 60,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(dto.ChallengeTOTPResponse{
		AccessToken:  resp.AccessToken,
		TokenType:    resp.TokenType,
		ExpiresIn:    resp.ExpiresIn,
		RefreshToken: resp.RefreshToken,
	})
}

func (c *MFASMSController) handleServiceError(w http.ResponseWriter, err error, log *zap.Logger) {
	switch err {
	case svc.ErrMFAMissingFields:
		httperrors.WriteError(w, httperrors.ErrMissingFields.WithDetail("mfa_token and code are required"))
	case svc.ErrMFATokenNotFound:
		httperrors.WriteError(w, httperrors.New(http.StatusBadRequest, "invalid_grant", "MFA token expired or not found"))
	case svc.ErrMFATokenInvalid:
		httperrors.WriteError(w, httperrors.New(http.StatusBadRequest, "invalid_request", "Invalid MFA token payload"))
	case svc.ErrMFATenantMismatch:
		httperrors.WriteError(w, httperrors.New(http.StatusUnauthorized, "invalid_client", "Tenant mismatch"))
	case svc.ErrMFASMSNotAvailable:
		httperrors.WriteError(w, httperrors.New(http.StatusBadRequest, "mfa_sms_not_available", "SMS factor not available"))
	case svc.ErrMFASMSRateLimited:
		httperrors.WriteError(w, httperrors.ErrRateLimitExceeded.WithDetail("SMS MFA rate limit exceeded"))
	case svc.ErrMFASMSInvalidCode:
		httperrors.WriteError(w, httperrors.New(http.StatusUnauthorized, "invalid_mfa_code", "Invalid SMS code"))
	case svc.ErrMFASMSProviderUnavailable:
		httperrors.WriteError(w, httperrors.New(http.StatusServiceUnavailable, "mfa_sms_unavailable", "SMS MFA temporarily unavailable"))
	case svc.ErrMFAStoreFailed:
		log.Error("store error", zap.Error(err))
		httperrors.WriteError(w, httperrors.New(http.StatusInternalServerError, "store_error", "Storage operation failed"))
	case svc.ErrMFACryptoFailed:
		log.Error("crypto error", zap.Error(err))
		httperrors.WriteError(w, httperrors.New(http.StatusInternalServerError, "crypto_failed", "Crypto operation failed"))
	default:
		log.Error("unexpected error", zap.Error(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
	}
}
