package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	"github.com/dropDatabas3/hellojohn/internal/http/helpers"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/auth"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

const (
	maxLoginBodySize = 64 * 1024 // 64KB
	contentTypeJSON  = "application/json; charset=utf-8"
)

// LoginController maneja el endpoint de login.
type LoginController struct {
	service svc.LoginService
}

// NewLoginController crea un nuevo controller de login.
func NewLoginController(service svc.LoginService) *LoginController {
	return &LoginController{service: service}
}

// Login maneja POST /v2/auth/login
func (c *LoginController) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("LoginController.Login"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Limitar body
	r.Body = http.MaxBytesReader(w, r.Body, maxLoginBodySize)
	defer r.Body.Close()

	// Parse request (JSON o form)
	var req dto.LoginRequest
	ct := strings.ToLower(r.Header.Get("Content-Type"))

	switch {
	case strings.Contains(ct, "application/json"):
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httperrors.WriteError(w, httperrors.ErrInvalidJSON)
			return
		}

	case strings.Contains(ct, "application/x-www-form-urlencoded"):
		if err := r.ParseForm(); err != nil {
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invalid form"))
			return
		}
		req.TenantID = r.FormValue("tenant_id")
		req.ClientID = r.FormValue("client_id")
		req.Email = r.FormValue("email")
		req.Password = r.FormValue("password")

	default:
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("unsupported content type"))
		return
	}

	// Read trusted device cookie (new canonical + legacy fallback)
	if cookie, err := r.Cookie("__Host-hj-trusted"); err == nil && cookie.Value != "" {
		req.TrustedDeviceToken = cookie.Value
	} else if cookie, err := r.Cookie("mfa_trust"); err == nil && cookie.Value != "" {
		req.TrustedDeviceToken = cookie.Value
	}

	// Extract client IP for bot protection validation
	req.RemoteIP = helpers.GetClientIP(r)

	// Llamar al service
	result, err := c.service.LoginPassword(ctx, req)
	if err != nil {
		log.Debug("login failed", logger.Err(err))
		writeLoginError(w, err)
		return
	}

	// Headers de seguridad
	w.Header().Set("Content-Type", contentTypeJSON)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// Responder según resultado
	if result.MFARequired {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(dto.MFARequiredResponse{
			MFARequired:      true,
			MFAToken:         result.MFAToken,
			AMR:              result.AMR,
			AvailableFactors: result.AvailableFactors,
			PreferredFactor:  result.PreferredFactor,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(dto.LoginResponse{
		AccessToken:  result.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    result.ExpiresIn,
		RefreshToken: result.RefreshToken,
	})
}

// ─── Helpers ───

func writeLoginError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, svc.ErrMissingFields):
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("email, password, tenant_id and client_id are required"))

	case errors.Is(err, svc.ErrInvalidClient):
		httperrors.WriteError(w, httperrors.ErrClientNotFound)

	case errors.Is(err, svc.ErrPasswordNotAllowed):
		httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail("password login is disabled"))

	case errors.Is(err, svc.ErrInvalidCredentials):
		httperrors.WriteError(w, httperrors.ErrInvalidCredentials)

	case errors.Is(err, svc.ErrUserDisabled):
		// 423 Locked - construimos el error manualmente
		w.Header().Set("Content-Type", contentTypeJSON)
		w.WriteHeader(http.StatusLocked)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":    "user_disabled",
			"message": "usuario deshabilitado",
		})

	case errors.Is(err, svc.ErrEmailNotVerified):
		httperrors.WriteError(w, httperrors.ErrEmailNotVerified)

	case errors.Is(err, svc.ErrNoDatabase):
		httperrors.WriteError(w, httperrors.ErrTenantNoDatabase)

	case errors.Is(err, svc.ErrTokenIssueFailed):
		httperrors.WriteError(w, httperrors.ErrInternalServerError.WithDetail("failed to issue tokens"))

	default:
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
	}
}
