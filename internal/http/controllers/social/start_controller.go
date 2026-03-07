package social

import (
	"errors"
	"net/http"
	"strings"

	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	"github.com/dropDatabas3/hellojohn/internal/http/helpers"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/social"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// StartController handles social login start endpoint.
type StartController struct {
	service svc.StartService
}

// NewStartController creates a new StartController.
func NewStartController(service svc.StartService) *StartController {
	return &StartController{service: service}
}

// Start handles GET /v2/auth/social/{provider}/start
func (c *StartController) Start(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("StartController.Start"))

	// Validate HTTP method
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Extract provider from path (Go 1.22+ path params)
	provider := r.PathValue("provider")
	if provider == "" {
		// Fallback: parse from URL path manually
		// Path expected: /v2/auth/social/{provider}/start
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v2/auth/social/"), "/")
		if len(parts) >= 1 {
			provider = parts[0]
		}
	}

	if provider == "" {
		log.Warn("missing provider in path")
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("missing provider"))
		return
	}

	// Resolve tenant (optional - from headers/query)
	tenantSlug := helpers.ResolveTenantSlug(r)
	if tenantSlug == "" {
		// Try query params as fallback (V1 compatibility)
		tenantSlug = r.URL.Query().Get("tenant")
		if tenantSlug == "" {
			tenantSlug = r.URL.Query().Get("tenant_id")
		}
	}

	if tenantSlug == "" {
		log.Warn("missing tenant")
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant required"))
		return
	}

	// Get other query params
	clientID := strings.TrimSpace(r.URL.Query().Get("client_id"))
	redirectURI := strings.TrimSpace(r.URL.Query().Get("redirect_uri"))

	if clientID == "" {
		log.Warn("missing client_id")
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("client_id required"))
		return
	}

	// Build base URL from request
	scheme := r.URL.Scheme
	if scheme == "" {
		scheme = "https"
		if strings.HasPrefix(r.Host, "localhost") || strings.HasPrefix(r.Host, "127.0.0.1") {
			scheme = "http"
		}
		// Check X-Forwarded-Proto header
		if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
			scheme = proto
		}
	}
	baseURL := scheme + "://" + r.Host

	// Call service
	result, err := c.service.Start(ctx, svc.StartRequest{
		Provider:    provider,
		TenantSlug:  tenantSlug,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		BaseURL:     baseURL,
	})

	if err != nil {
		log.Error("start failed",
			logger.String("provider", provider),
			logger.TenantID(tenantSlug),
			logger.Err(err),
		)

		switch {
		case errors.Is(err, svc.ErrStartMissingTenant):
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant required"))
		case errors.Is(err, svc.ErrStartMissingClientID):
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("client_id required"))
		case errors.Is(err, svc.ErrStartProviderUnknown):
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("unknown provider"))
		case errors.Is(err, svc.ErrStartProviderDisabled):
			httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("provider not enabled"))
		case errors.Is(err, svc.ErrStartInvalidClient):
			httperrors.WriteError(w, httperrors.New(
				http.StatusUnauthorized,
				"unauthorized_client",
				"Configuracion de cliente invalida.",
			))
		case errors.Is(err, svc.ErrStartInvalidRedirect):
			httperrors.WriteError(w, httperrors.New(
				http.StatusBadRequest,
				"invalid_redirect_uri",
				"La URL de callback es invalida.",
			))
		case errors.Is(err, svc.ErrStartRedirectNotAllowed):
			httperrors.WriteError(w, httperrors.New(
				http.StatusBadRequest,
				"redirect_uri_not_allowed",
				"La URL de callback no esta permitida para este cliente.",
			))
		default:
			httperrors.WriteError(w, httperrors.ErrInternalServerError)
		}
		return
	}

	// Set no-cache headers before redirect
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// Redirect to OAuth provider
	http.Redirect(w, r, result.RedirectURL, http.StatusFound)

	log.Debug("redirect to provider",
		logger.String("provider", provider),
		logger.TenantID(tenantSlug),
	)
}
