package email

import (
	"encoding/json"
	"net/http"
	"net/url"

	"go.uber.org/zap"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/email"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/email"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// FlowsController handles email verification and password reset endpoints.
type FlowsController struct {
	service svc.FlowsService
}

// NewFlowsController creates a new email flows controller.
func NewFlowsController(service svc.FlowsService) *FlowsController {
	return &FlowsController{service: service}
}

// VerifyEmailStart handles POST /v2/auth/verify-email/start.
func (c *FlowsController) VerifyEmailStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("FlowsController.VerifyEmailStart"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Limit body size
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10) // 32KB

	// Parse request
	var req dto.VerifyEmailStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invalid JSON"))
		return
	}

	// Get tenant from middleware
	tda := mw.MustGetTenant(ctx)

	// Check if authenticated - pass as pointer
	var userIDPtr *string
	if uid := mw.GetUserID(ctx); uid != "" {
		userIDPtr = &uid
	}

	// Call service
	err := c.service.VerifyEmailStart(ctx, tda, req, userIDPtr)
	if err != nil {
		switch err {
		case svc.ErrFlowsMissingTenant, svc.ErrFlowsMissingClient, svc.ErrFlowsMissingEmail, svc.ErrFlowsTenantMismatch:
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(err.Error()))
		case svc.ErrFlowsNoDatabase:
			httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("database not available"))
		case svc.ErrFlowsUserNotFound:
			// Anti-enumeration: return 204 even if user not found
			w.WriteHeader(http.StatusNoContent)
			return
		default:
			log.Error("verify email start error", logger.Err(err))
			httperrors.WriteError(w, httperrors.ErrInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
	log.Debug("verify email start initiated")
}

// VerifyEmailConfirm handles GET /v2/auth/verify-email.
func (c *FlowsController) VerifyEmailConfirm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("FlowsController.VerifyEmailConfirm"))

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Parse query params
	q := r.URL.Query()
	req := dto.VerifyEmailConfirmRequest{
		Token:       q.Get("token"),
		RedirectURI: q.Get("redirect_uri"),
		ClientID:    q.Get("client_id"),
		TenantID:    q.Get("tenant_id"),
	}

	if req.Token == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("token is required"))
		return
	}

	// Get tenant from middleware
	tda := mw.MustGetTenant(ctx)

	// Call service
	result, err := c.service.VerifyEmailConfirm(ctx, tda, req)
	if err != nil {
		switch err {
		case svc.ErrFlowsMissingToken, svc.ErrFlowsInvalidToken, svc.ErrFlowsTenantMismatch:
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(err.Error()))
		case svc.ErrFlowsNoDatabase:
			httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("database not available"))
		default:
			log.Error("verify email confirm error", logger.Err(err))
			httperrors.WriteError(w, httperrors.ErrInternalServerError)
		}
		return
	}

	// Redirect if redirect_uri provided
	if result.Redirect != "" {
		// Validar y mergear query
		if u, err := url.Parse(result.Redirect); err == nil {
			q := u.Query()
			q.Set("status", "verified")
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
		// Fallback si falla parse -> NO REDIRECT (Security hardening)
		log.Warn("failed to parse redirect uri, defaulting to json response", zap.String("uri", result.Redirect))
	}

	// Return JSON
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "verified"})

	log.Debug("verify email confirmed")
}

// ForgotPassword handles POST /v2/auth/forgot.
func (c *FlowsController) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("FlowsController.ForgotPassword"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Limit body size
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10) // 32KB

	// Parse request
	var req dto.ForgotPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invalid JSON"))
		return
	}

	// Get tenant from middleware
	tda := mw.MustGetTenant(ctx)

	// Call service
	err := c.service.ForgotPassword(ctx, tda, req)
	if err != nil {
		switch err {
		case svc.ErrFlowsMissingTenant, svc.ErrFlowsMissingClient, svc.ErrFlowsMissingEmail, svc.ErrFlowsTenantMismatch:
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(err.Error()))
		case svc.ErrFlowsNoDatabase:
			httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("database not available"))
		default:
			log.Error("forgot password error", logger.Err(err))
			httperrors.WriteError(w, httperrors.ErrInternalServerError)
		}
		return
	}

	// Always return OK (anti-enumeration)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

	log.Debug("forgot password initiated")
}

// ResetPassword handles POST /v2/auth/reset.
func (c *FlowsController) ResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("FlowsController.ResetPassword"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Limit body size
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10) // 32KB

	// Parse request
	var req dto.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invalid JSON"))
		return
	}

	// Get tenant from middleware
	tda := mw.MustGetTenant(ctx)

	// Call service
	result, err := c.service.ResetPassword(ctx, tda, req)
	if err != nil {
		switch err {
		case svc.ErrFlowsMissingTenant, svc.ErrFlowsMissingClient, svc.ErrFlowsMissingToken, svc.ErrFlowsMissingPassword, svc.ErrFlowsTenantMismatch:
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(err.Error()))
		case svc.ErrFlowsInvalidToken:
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("token invalid or expired"))
		case svc.ErrFlowsWeakPassword:
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("password does not meet policy"))
		case svc.ErrFlowsNoDatabase:
			httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("database not available"))
		default:
			log.Error("reset password error", logger.Err(err))
			httperrors.WriteError(w, httperrors.ErrInternalServerError)
		}
		return
	}

	// Set anti-cache headers
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if result.AutoLogin && result.AccessToken != "" {
		// Return tokens
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  result.AccessToken,
			"refresh_token": result.RefreshToken,
			"token_type":    "Bearer",
			"expires_in":    result.ExpiresIn,
		})
	} else {
		// No auto-login
		w.WriteHeader(http.StatusNoContent)
	}

	log.Debug("password reset completed")
}
