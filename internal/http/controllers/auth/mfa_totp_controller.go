// Package auth contains the MFA TOTP controller.
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

// MFATOTPController handles MFA TOTP endpoints.
type MFATOTPController struct {
	service svc.MFATOTPService
}

// NewMFATOTPController creates the controller.
func NewMFATOTPController(s svc.MFATOTPService) *MFATOTPController {
	return &MFATOTPController{service: s}
}

// Enroll handles POST /v2/mfa/totp/enroll
// Requires: authenticated user (claims in context)
func (c *MFATOTPController) Enroll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("mfa.totp.enroll"))

	// Method check
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Get tenant from context (set by middleware)
	tda := middlewares.GetTenant(ctx)
	if tda == nil {
		log.Warn("tenant not resolved")
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant required"))
		return
	}
	tenantSlug := tda.Slug()

	// Get user from claims
	claims := middlewares.GetClaims(ctx)
	userID := ""
	email := ""
	if claims != nil {
		userID = middlewares.ClaimString(claims, "sub")
		email = middlewares.ClaimString(claims, "email")
	}
	if userID == "" {
		log.Warn("user not authenticated")
		httperrors.WriteError(w, httperrors.ErrUnauthorized)
		return
	}

	// Call service
	result, err := c.service.Enroll(ctx, tenantSlug, userID, email)
	if err != nil {
		c.handleServiceError(w, err, log)
		return
	}

	// Response with no-store (contains secret!)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	resp := dto.EnrollTOTPResponse{
		SecretBase32: result.SecretBase32,
		OTPAuthURL:   result.OTPAuthURL,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// Verify handles POST /v2/mfa/totp/verify
// Requires: authenticated user (claims in context)
func (c *MFATOTPController) Verify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("mfa.totp.verify"))

	// Method check
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Limit body
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10) // 4KB for small JSON

	// Get tenant from context
	tda := middlewares.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant required"))
		return
	}
	tenantSlug := tda.Slug()

	// Get user from claims
	claims := middlewares.GetClaims(ctx)
	userID := ""
	if claims != nil {
		userID = middlewares.ClaimString(claims, "sub")
	}
	if userID == "" {
		httperrors.WriteError(w, httperrors.ErrUnauthorized)
		return
	}

	// Parse request
	var req dto.VerifyTOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("failed to parse request", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	if strings.TrimSpace(req.Code) == "" {
		httperrors.WriteError(w, httperrors.ErrMissingFields.WithDetail("code is required"))
		return
	}

	// Call service
	result, err := c.service.Verify(ctx, tenantSlug, userID, req.Code)
	if err != nil {
		c.handleServiceError(w, err, log)
		return
	}

	// Response with no-store (may contain recovery codes!)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	resp := dto.VerifyTOTPResponse{
		Enabled:       result.Enabled,
		RecoveryCodes: result.RecoveryCodes,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// Disable handles POST /v2/mfa/totp/disable
// Requires: authenticated user (claims in context)
func (c *MFATOTPController) Disable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("mfa.totp.disable"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)

	tda := middlewares.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant required"))
		return
	}
	tenantSlug := tda.Slug()

	claims := middlewares.GetClaims(ctx)
	userID := ""
	if claims != nil {
		userID = middlewares.ClaimString(claims, "sub")
	}
	if userID == "" {
		httperrors.WriteError(w, httperrors.ErrUnauthorized)
		return
	}

	var req dto.DisableTOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	err := c.service.Disable(ctx, tenantSlug, userID, req.Password, req.Code, req.Recovery)
	if err != nil {
		c.handleServiceError(w, err, log)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(dto.DisableTOTPResponse{Disabled: true})
}

// RotateRecovery handles POST /v2/mfa/recovery/rotate
// Requires: authenticated user (claims in context)
func (c *MFATOTPController) RotateRecovery(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("mfa.recovery.rotate"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)

	tda := middlewares.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant required"))
		return
	}
	tenantSlug := tda.Slug()

	claims := middlewares.GetClaims(ctx)
	userID := ""
	if claims != nil {
		userID = middlewares.ClaimString(claims, "sub")
	}
	if userID == "" {
		httperrors.WriteError(w, httperrors.ErrUnauthorized)
		return
	}

	var req dto.RotateRecoveryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	result, err := c.service.RotateRecovery(ctx, tenantSlug, userID, req.Password, req.Code, req.Recovery)
	if err != nil {
		c.handleServiceError(w, err, log)
		return
	}

	// No-store for sensitive recovery codes
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(dto.RotateRecoveryResponse{
		Rotated:       true,
		RecoveryCodes: result.RecoveryCodes,
	})
}

// Challenge handles POST /v2/mfa/totp/challenge
// Identifies user via mfa_token (from cache) and issues tokens.
func (c *MFATOTPController) Challenge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("mfa.totp.challenge"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 64<<10) // 64KB limit

	tda := middlewares.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant required"))
		return
	}
	tenantSlug := tda.Slug()

	var req dto.ChallengeTOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	svcReq := svc.ChallengeTOTPRequest{
		MFAToken:       req.MFAToken,
		Code:           req.Code,
		Recovery:       req.Recovery,
		RememberDevice: req.RememberDevice,
	}

	resp, err := c.service.Challenge(ctx, tenantSlug, svcReq)
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
	// Response structure matches dto.ChallengeTOTPResponse (access_token, etc.)
	// We can cast or map. The service returns *auth.ChallengeTOTPResponse which maps to DTO.
	dtoResp := dto.ChallengeTOTPResponse{
		AccessToken:  resp.AccessToken,
		TokenType:    resp.TokenType,
		ExpiresIn:    resp.ExpiresIn,
		RefreshToken: resp.RefreshToken,
	}
	_ = json.NewEncoder(w).Encode(dtoResp)
}

func (c *MFATOTPController) handleServiceError(w http.ResponseWriter, err error, log *zap.Logger) {
	switch err {
	case svc.ErrMFANotInitialized:
		httperrors.WriteError(w, httperrors.New(http.StatusBadRequest, "mfa_not_initialized", "MFA not enrolled, call enroll first"))
	case svc.ErrMFAInvalidCode:
		httperrors.WriteError(w, httperrors.New(http.StatusUnauthorized, "invalid_mfa_code", "Invalid MFA code"))
	case svc.ErrRecoveryCodeRateLimited:
		httperrors.WriteError(w, httperrors.ErrRateLimitExceeded)
	case svc.ErrMFACryptoFailed:
		log.Error("crypto error", zap.Error(err))
		httperrors.WriteError(w, httperrors.New(http.StatusInternalServerError, "crypto_failed", "Crypto operation failed"))
	case svc.ErrMFAStoreFailed:
		log.Error("store error", zap.Error(err))
		httperrors.WriteError(w, httperrors.New(http.StatusInternalServerError, "store_error", "Storage operation failed"))
	case svc.ErrMFANotSupported:
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("MFA not supported for this tenant"))
	case svc.ErrMFAInvalidPassword:
		httperrors.WriteError(w, httperrors.New(http.StatusUnauthorized, "invalid_password", "Invalid password"))
	case svc.ErrMFAUserNotFound:
		httperrors.WriteError(w, httperrors.New(http.StatusNotFound, "user_not_found", "User not found"))
	case svc.ErrMFAMissingFields:
		httperrors.WriteError(w, httperrors.ErrMissingFields.WithDetail("password and code/recovery required"))
	case svc.ErrMFATokenNotFound:
		httperrors.WriteError(w, httperrors.New(http.StatusBadRequest, "invalid_grant", "MFA token expired or not found"))
	case svc.ErrMFATokenInvalid:
		httperrors.WriteError(w, httperrors.New(http.StatusBadRequest, "invalid_request", "Invalid MFA token payload"))
	case svc.ErrMFATenantMismatch:
		httperrors.WriteError(w, httperrors.New(http.StatusUnauthorized, "invalid_client", "Tenant mismatch"))
	default:
		log.Error("unexpected error", zap.Error(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
	}
}
