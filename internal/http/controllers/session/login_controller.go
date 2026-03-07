package session

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/session"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	"github.com/dropDatabas3/hellojohn/internal/http/helpers"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/session"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// LoginController handles POST /v2/session/login.
type LoginController struct {
	service svc.LoginService
	config  dto.LoginConfig
}

// NewLoginController creates a new session login controller.
func NewLoginController(service svc.LoginService, config dto.LoginConfig) *LoginController {
	return &LoginController{
		service: service,
		config:  config,
	}
}

// Login handles the session login request.
// Authenticates user with email/password and creates a session cookie.
func (c *LoginController) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("LoginController.Login"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Limit body size
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10) // 32KB

	// Parse request
	var req dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invalid JSON"))
		return
	}

	// Get tenant from middleware
	tda := mw.MustGetTenant(ctx)
	effectiveCfg := c.effectiveLoginConfig(tda)

	// Call service
	result, err := c.service.Login(ctx, tda, req)
	if err != nil {
		switch err {
		case svc.ErrLoginMissingTenant:
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant_id or client_id is required"))
		case svc.ErrLoginMissingEmail:
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("email is required"))
		case svc.ErrLoginMissingPassword:
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("password is required"))
		case svc.ErrLoginInvalidCredentials:
			httperrors.WriteError(w, httperrors.ErrInvalidCredentials)
		case svc.ErrLoginNoDatabase:
			httperrors.WriteError(w, httperrors.ErrTenantNoDatabase)
		case svc.ErrLoginSessionFailed:
			httperrors.WriteError(w, httperrors.ErrInternalServerError)
		default:
			log.Error("login error", logger.Err(err))
			httperrors.WriteError(w, httperrors.ErrInternalServerError)
		}
		return
	}

	// Set session cookie
	cookie := c.service.BuildSessionCookie(result.SessionID, effectiveCfg)
	http.SetCookie(w, cookie)

	// Set anti-cache headers
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// Return 204 No Content (cookie was set)
	w.WriteHeader(http.StatusNoContent)

	log.Debug("session login successful")
}

func (c *LoginController) effectiveLoginConfig(tda store.TenantDataAccess) dto.LoginConfig {
	cfg := c.config
	if tda == nil {
		return cfg
	}

	settings := tda.Settings()

	if settings.SessionLifetimeSeconds > 0 {
		cfg.TTL = time.Duration(settings.SessionLifetimeSeconds) * time.Second
	}

	applyTenantCookiePolicy(&cfg, settings.CookiePolicy)
	return cfg
}

func applyTenantCookiePolicy(cfg *dto.LoginConfig, policy *repository.CookiePolicy) {
	helpers.ApplyTenantCookiePolicyToLoginConfig(cfg, policy)
}
