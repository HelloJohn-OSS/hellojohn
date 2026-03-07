package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/auth"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// PasswordlessController maneja endpoints de autenticación sin contraseña.
type PasswordlessController struct {
	service svc.PasswordlessService
}

// NewPasswordlessController crea un nuevo controlador passwordless.
func NewPasswordlessController(service svc.PasswordlessService) *PasswordlessController {
	return &PasswordlessController{service: service}
}

// SendMagicLink maneja POST /v2/auth/magic-link/send
func (c *PasswordlessController) SendMagicLink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("Passwordless.SendMagicLink"))

	if r.Method != http.MethodPost {
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	var req svc.MagicLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}
	defer r.Body.Close()

	if err := c.service.SendMagicLink(ctx, req); err != nil {
		log.Debug("send magic link failed", logger.Err(err))
		writePasswordlessError(w, err)
		return
	}

	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
}

// VerifyMagicLink maneja POST /v2/auth/magic-link/verify
func (c *PasswordlessController) VerifyMagicLink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("Passwordless.VerifyMagicLink"))

	if r.Method != http.MethodPost {
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}
	defer r.Body.Close()

	result, err := c.service.VerifyMagicLink(ctx, req.Token)
	if err != nil {
		log.Debug("verify magic link failed", logger.Err(err))
		writePasswordlessError(w, err)
		return
	}

	w.Header().Set("Content-Type", contentTypeJSON)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(dto.LoginResponse{
		AccessToken:  result.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    result.ExpiresIn,
		RefreshToken: result.RefreshToken,
	})
}

// ConsumeMagicLink maneja GET /v2/auth/magic-link/consume/{token}
func (c *PasswordlessController) ConsumeMagicLink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("Passwordless.ConsumeMagicLink"))

	if r.Method != http.MethodGet {
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	const prefix = "/v2/auth/magic-link/consume/"
	token := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, prefix))
	if token == "" || token == r.URL.Path {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("missing token"))
		return
	}

	redirectURL, err := c.service.ConsumeMagicLink(ctx, token)
	if err != nil {
		log.Debug("consume magic link failed", logger.Err(err))
		writePasswordlessError(w, err)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// ExchangeMagicLinkCode maneja POST /v2/auth/magic-link/exchange
func (c *PasswordlessController) ExchangeMagicLinkCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("Passwordless.ExchangeMagicLinkCode"))

	if r.Method != http.MethodPost {
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	var req svc.ExchangeMagicLinkCodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}
	defer r.Body.Close()

	result, err := c.service.ExchangeMagicLinkCode(ctx, req.Code)
	if err != nil {
		log.Debug("exchange magic link code failed", logger.Err(err))
		writePasswordlessError(w, err)
		return
	}

	w.Header().Set("Content-Type", contentTypeJSON)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(dto.LoginResponse{
		AccessToken:  result.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    result.ExpiresIn,
		RefreshToken: result.RefreshToken,
	})
}

// SendOTP maneja POST /v2/auth/otp/send
func (c *PasswordlessController) SendOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("Passwordless.SendOTP"))

	if r.Method != http.MethodPost {
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	var req svc.OTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}
	defer r.Body.Close()

	if err := c.service.SendOTPEmail(ctx, req); err != nil {
		log.Debug("send otp failed", logger.Err(err))
		writePasswordlessError(w, err)
		return
	}

	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
}

// VerifyOTP maneja POST /v2/auth/otp/verify
func (c *PasswordlessController) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("Passwordless.VerifyOTP"))

	if r.Method != http.MethodPost {
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	var req svc.VerifyOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}
	defer r.Body.Close()

	result, err := c.service.VerifyOTPEmail(ctx, req)
	if err != nil {
		log.Debug("verify otp failed", logger.Err(err))
		writePasswordlessError(w, err)
		return
	}

	w.Header().Set("Content-Type", contentTypeJSON)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(dto.LoginResponse{
		AccessToken:  result.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    result.ExpiresIn,
		RefreshToken: result.RefreshToken,
	})
}

// Helper func para manejo de errores passwordless
func writePasswordlessError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, svc.ErrMagicLinkDisabled), errors.Is(err, svc.ErrOTPDisabled), strings.Contains(err.Error(), "disabled"):
		httperrors.WriteError(w, httperrors.ErrForbidden.WithDetail(err.Error()))
	case errors.Is(err, svc.ErrRateLimited), errors.Is(err, svc.ErrTooManyAttempts), errors.Is(err, svc.ErrDailyLimitExceeded):
		httperrors.WriteError(w, httperrors.ErrRateLimitExceeded.WithDetail(err.Error()))
	case errors.Is(err, svc.ErrInvalidOrExpiredMagicLink), errors.Is(err, svc.ErrInvalidOrExpiredOTP), errors.Is(err, svc.ErrInvalidOrExpiredMagicCode), errors.Is(err, svc.ErrAuthenticationFailed):
		httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail(err.Error()))
	case errors.Is(err, svc.ErrInvalidRedirectURI):
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invalid redirect uri"))
	default:
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
	}
}
