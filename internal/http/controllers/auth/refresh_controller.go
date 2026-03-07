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

const maxRefreshBodySize = 8 * 1024 // 8KB

// RefreshController handles POST /v2/auth/refresh
type RefreshController struct {
	service svc.RefreshService
}

// NewRefreshController creates a new controller for refresh.
func NewRefreshController(service svc.RefreshService) *RefreshController {
	return &RefreshController{service: service}
}

// Refresh handles POST /v2/auth/refresh
func (c *RefreshController) Refresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("RefreshController.Refresh"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Limit body size
	r.Body = http.MaxBytesReader(w, r.Body, maxRefreshBodySize)
	defer r.Body.Close()

	// Parse request
	var req dto.RefreshRequest
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
		req.RefreshToken = r.FormValue("refresh_token")

	default:
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("unsupported content type"))
		return
	}

	// Resolve tenant from context/headers
	tenantSlug := helpers.ResolveTenantSlug(r)

	// Call service
	result, err := c.service.Refresh(ctx, req, tenantSlug)
	if err != nil {
		log.Debug("refresh failed", logger.Err(err))
		writeRefreshError(w, err)
		return
	}

	// Security headers
	w.Header().Set("Content-Type", contentTypeJSON)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(dto.RefreshResponse{
		AccessToken:  result.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    result.ExpiresIn,
		RefreshToken: result.RefreshToken,
	})
}

// ─── Error Mapping ───

func writeRefreshError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, svc.ErrMissingRefreshFields):
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("client_id and refresh_token are required"))

	case errors.Is(err, svc.ErrInvalidRefreshToken):
		httperrors.WriteError(w, httperrors.ErrSessionExpired)

	case errors.Is(err, svc.ErrRefreshTokenRevoked):
		httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail("refresh token is revoked"))

	case errors.Is(err, svc.ErrRefreshTokenReuse):
		httperrors.WriteError(w, httperrors.ErrRefreshTokenReuse)

	case errors.Is(err, svc.ErrClientMismatch):
		httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail("client_id mismatch"))

	case errors.Is(err, svc.ErrRefreshUserDisabled):
		w.Header().Set("Content-Type", contentTypeJSON)
		w.WriteHeader(http.StatusLocked)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":    "user_disabled",
			"message": "usuario deshabilitado",
		})

	case errors.Is(err, svc.ErrNoDatabase):
		httperrors.WriteError(w, httperrors.ErrTenantNoDatabase)

	case errors.Is(err, svc.ErrRefreshIssueFailed):
		httperrors.WriteError(w, httperrors.ErrInternalServerError.WithDetail("failed to issue tokens"))

	case errors.Is(err, svc.ErrInvalidClient):
		httperrors.WriteError(w, httperrors.ErrClientNotFound)

	default:
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
	}
}
