package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	neturl "net/url"
	"strings"

	cache "github.com/dropDatabas3/hellojohn/internal/cache"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	sessiondto "github.com/dropDatabas3/hellojohn/internal/http/dto/session"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	"github.com/dropDatabas3/hellojohn/internal/http/helpers"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/auth"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

const maxLogoutBodySize = 4 * 1024 // 4KB

// LogoutController handles POST /v2/auth/logout and /v2/auth/logout-all
type LogoutController struct {
	service      svc.LogoutService
	logoutConfig sessiondto.SessionLogoutConfig
	dal          store.DataAccessLayer
	sessionCache cache.Client
}

// NewLogoutController creates a new controller for logout.
func NewLogoutController(
	service svc.LogoutService,
	logoutConfig sessiondto.SessionLogoutConfig,
	dal store.DataAccessLayer,
	sessionCache cache.Client,
) *LogoutController {
	return &LogoutController{
		service:      service,
		logoutConfig: logoutConfig,
		dal:          dal,
		sessionCache: sessionCache,
	}
}

// Logout handles POST /v2/auth/logout (refresh token revocation + session cleanup).
func (c *LogoutController) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("LogoutController.Logout"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxLogoutBodySize)
	defer r.Body.Close()

	var req dto.LogoutRequest
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invalid request body"))
		return
	}
	if err := parseLogoutRequest(raw, r.Header.Get("Content-Type"), &req); err != nil {
		httperrors.WriteError(w, err)
		return
	}

	// Read session cookie and pass it to unified logout service.
	cookieName := c.logoutConfig.CookieName
	if strings.TrimSpace(cookieName) == "" {
		cookieName = "sid"
	}
	if ck, err := r.Cookie(cookieName); err == nil && ck != nil {
		req.SessionID = strings.TrimSpace(ck.Value)
	}

	effectiveLogoutCfg := c.effectiveLogoutConfig(ctx, r, req)
	tenantSlug := c.resolveRequestTenantSlug(ctx, r, req)
	result, err := c.service.Logout(ctx, req, tenantSlug)
	if err != nil {
		log.Debug("logout failed", logger.Err(err))
		writeLogoutError(w, err)
		return
	}

	// Clear browser cookie if it was present.
	if req.SessionID != "" {
		http.SetCookie(w, helpers.BuildDeletionCookie(
			cookieName,
			effectiveLogoutCfg.CookieDomain,
			effectiveLogoutCfg.SameSite,
			effectiveLogoutCfg.Secure,
		))
	}

	// If a valid post_logout_redirect_uri was requested, return it.
	if result != nil && strings.TrimSpace(result.PostLogoutRedirectURI) != "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(result)
		return
	}

	// Success default: 204 No Content
	w.WriteHeader(http.StatusNoContent)
}

// LogoutAll handles POST /v2/auth/logout-all (mass token revocation)
func (c *LogoutController) LogoutAll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("LogoutController.LogoutAll"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxLogoutBodySize)
	defer r.Body.Close()

	var req dto.LogoutAllRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	tenantSlug := c.resolveRequestTenantSlug(ctx, r, dto.LogoutRequest{})

	err := c.service.LogoutAll(ctx, req, tenantSlug)
	if err != nil {
		log.Debug("logout-all failed", logger.Err(err))
		writeLogoutError(w, err)
		return
	}

	// Success: 204 No Content
	w.WriteHeader(http.StatusNoContent)
}

func (c *LogoutController) effectiveLogoutConfig(ctx context.Context, r *http.Request, req dto.LogoutRequest) sessiondto.SessionLogoutConfig {
	cfg := c.logoutConfig
	tenantSlug := c.resolveEffectiveTenantForCookiePolicy(ctx, r, req)
	if tenantSlug == "" || c.dal == nil {
		return cfg
	}

	tda, err := c.dal.ForTenant(ctx, tenantSlug)
	if err != nil || tda == nil {
		return cfg
	}
	settings := tda.Settings()
	if settings == nil {
		return cfg
	}

	helpers.ApplyTenantCookiePolicyToLogoutConfig(&cfg, settings.CookiePolicy)
	return cfg
}

func (c *LogoutController) resolveEffectiveTenantForCookiePolicy(ctx context.Context, r *http.Request, req dto.LogoutRequest) string {
	requestTenant := c.resolveRequestTenantSlug(ctx, r, req)
	sessionTenant := c.resolveTenantFromSession(ctx, req.SessionID)
	// Security rule: if request and session tenants differ, session tenant wins.
	if sessionTenant != "" {
		return sessionTenant
	}
	return requestTenant
}

func (c *LogoutController) resolveRequestTenantSlug(ctx context.Context, r *http.Request, req dto.LogoutRequest) string {
	if tda := mw.GetTenant(ctx); tda != nil {
		if slug := strings.TrimSpace(tda.Slug()); slug != "" {
			return slug
		}
		if id := strings.TrimSpace(tda.ID()); id != "" {
			return id
		}
	}

	if slug := strings.TrimSpace(helpers.ResolveTenantSlug(r)); slug != "" {
		return slug
	}

	return strings.TrimSpace(req.TenantID)
}

func (c *LogoutController) resolveTenantFromSession(ctx context.Context, sessionID string) string {
	if c.sessionCache == nil {
		return ""
	}

	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return ""
	}

	key := "sid:" + tokens.SHA256Base64URL(sessionID)
	raw, err := c.sessionCache.Get(ctx, key)
	if err != nil || strings.TrimSpace(raw) == "" {
		return ""
	}

	var payload sessiondto.SessionPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return ""
	}
	return strings.TrimSpace(payload.TenantID)
}

// â”€â”€â”€ Error Mapping â”€â”€â”€

func writeLogoutError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, svc.ErrLogoutMissingFields):
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("missing required fields"))

	case errors.Is(err, svc.ErrLogoutInvalidClient):
		httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail("client_id mismatch"))

	case errors.Is(err, svc.ErrLogoutNoDatabase):
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("database not available"))

	case errors.Is(err, svc.ErrLogoutNotSupported):
		httperrors.WriteError(w, httperrors.ErrNotImplemented.WithDetail("mass revocation is not supported"))

	case errors.Is(err, svc.ErrLogoutFailed):
		httperrors.WriteError(w, httperrors.ErrInternalServerError.WithDetail("failed to revoke tokens"))

	default:
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
	}
}

func parseLogoutRequest(raw []byte, contentType string, req *dto.LogoutRequest) error {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}

	body := strings.TrimSpace(string(raw))
	if body == "" {
		// Empty body is valid for session-only logout.
		return nil
	}

	switch ct {
	case "application/json":
		if err := json.Unmarshal(raw, req); err != nil {
			return httperrors.ErrInvalidJSON
		}
		return nil

	case "application/x-www-form-urlencoded":
		values, err := neturl.ParseQuery(body)
		if err != nil {
			return httperrors.ErrBadRequest.WithDetail("invalid form")
		}
		req.TenantID = values.Get("tenant_id")
		req.ClientID = values.Get("client_id")
		req.RefreshToken = values.Get("refresh_token")
		req.PostLogoutRedirectURI = values.Get("post_logout_redirect_uri")
		return nil

	case "":
		if err := json.Unmarshal(raw, req); err == nil {
			return nil
		}
		values, err := neturl.ParseQuery(body)
		if err != nil {
			return httperrors.ErrInvalidJSON
		}
		req.TenantID = values.Get("tenant_id")
		req.ClientID = values.Get("client_id")
		req.RefreshToken = values.Get("refresh_token")
		req.PostLogoutRedirectURI = values.Get("post_logout_redirect_uri")
		return nil

	default:
		// Backward compatibility: try JSON first, then form.
		if err := json.Unmarshal(raw, req); err == nil {
			return nil
		}
		values, err := neturl.ParseQuery(body)
		if err == nil {
			req.TenantID = values.Get("tenant_id")
			req.ClientID = values.Get("client_id")
			req.RefreshToken = values.Get("refresh_token")
			req.PostLogoutRedirectURI = values.Get("post_logout_redirect_uri")
			return nil
		}
		return httperrors.ErrBadRequest.WithDetail("unsupported content type")
	}
}
