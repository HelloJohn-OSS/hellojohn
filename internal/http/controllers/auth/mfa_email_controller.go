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

// MFAEmailController handles Email MFA endpoints.
type MFAEmailController struct {
	service svc.MFAEmailService
}

// NewMFAEmailController creates a new Email MFA controller.
func NewMFAEmailController(s svc.MFAEmailService) *MFAEmailController {
	return &MFAEmailController{service: s}
}

// Send handles POST /v2/mfa/email/send.
func (c *MFAEmailController) Send(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("mfa.email.send"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}
	if c.service == nil {
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("email mfa not configured"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)

	tda := middlewares.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant required"))
		return
	}
	tenantSlug := tda.Slug()

	var req dto.SendEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	resp, err := c.service.Send(ctx, tenantSlug, svc.SendEmailRequest{
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
	_ = json.NewEncoder(w).Encode(dto.SendEmailResponse{
		Sent:      resp.Sent,
		ExpiresIn: resp.ExpiresIn,
	})
}

// Challenge handles POST /v2/mfa/email/challenge.
func (c *MFAEmailController) Challenge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("mfa.email.challenge"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}
	if c.service == nil {
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("email mfa not configured"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)

	tda := middlewares.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant required"))
		return
	}
	tenantSlug := tda.Slug()

	var req dto.ChallengeEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	resp, err := c.service.Challenge(ctx, tenantSlug, svc.ChallengeEmailRequest{
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

func (c *MFAEmailController) handleServiceError(w http.ResponseWriter, err error, log *zap.Logger) {
	switch err {
	case svc.ErrMFAMissingFields:
		httperrors.WriteError(w, httperrors.ErrMissingFields.WithDetail("mfa_token and code are required"))
	case svc.ErrMFATokenNotFound:
		httperrors.WriteError(w, httperrors.New(http.StatusBadRequest, "invalid_grant", "MFA token expired or not found"))
	case svc.ErrMFATokenInvalid:
		httperrors.WriteError(w, httperrors.New(http.StatusBadRequest, "invalid_request", "Invalid MFA token payload"))
	case svc.ErrMFATenantMismatch:
		httperrors.WriteError(w, httperrors.New(http.StatusUnauthorized, "invalid_client", "Tenant mismatch"))
	case svc.ErrMFAEmailNotAvailable:
		httperrors.WriteError(w, httperrors.New(http.StatusBadRequest, "mfa_email_not_available", "Email factor not available"))
	case svc.ErrMFAEmailRateLimited:
		httperrors.WriteError(w, httperrors.ErrRateLimitExceeded.WithDetail("Email MFA rate limit exceeded"))
	case svc.ErrMFAEmailInvalidCode:
		httperrors.WriteError(w, httperrors.New(http.StatusUnauthorized, "invalid_mfa_code", "Invalid email code"))
	case svc.ErrMFAEmailProviderUnavailable:
		httperrors.WriteError(w, httperrors.New(http.StatusServiceUnavailable, "mfa_email_unavailable", "Email MFA temporarily unavailable"))
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
