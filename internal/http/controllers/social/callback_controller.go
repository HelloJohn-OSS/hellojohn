package social

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/social"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// CallbackController handles social login callback endpoint.
type CallbackController struct {
	service     svc.CallbackService
	stateSigner svc.StateSigner // To extract redirect_uri for error redirects
}

// NewCallbackController creates a new CallbackController.
func NewCallbackController(service svc.CallbackService, stateSigner svc.StateSigner) *CallbackController {
	return &CallbackController{service: service, stateSigner: stateSigner}
}

// Callback handles GET/POST /v2/auth/social/{provider}/callback.
// Apple uses POST with response_mode=form_post.
func (c *CallbackController) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("CallbackController.Callback"))

	// Validate HTTP method (GET for most providers, POST for Apple form_post)
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Extract provider from path (Go 1.22+ path params)
	provider := r.PathValue("provider")
	if provider == "" {
		// Fallback: parse from URL path manually
		// Path expected: /v2/auth/social/{provider}/callback
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

	// Parse query + form body parameters (form_post callbacks).
	if err := r.ParseForm(); err != nil {
		log.Warn("failed to parse callback form", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invalid callback payload"))
		return
	}

	// Check for IDP error first
	if idpError := strings.TrimSpace(r.Form.Get("error")); idpError != "" {
		idpDesc := strings.TrimSpace(r.Form.Get("error_description"))
		log.Warn("IDP error",
			logger.String("provider", provider),
			logger.String("error", idpError),
			logger.String("description", idpDesc),
		)

		// Try to redirect with error if we can extract redirect_uri from state
		state := strings.TrimSpace(r.Form.Get("state"))
		if redirectURI := c.extractRedirectURI(state); redirectURI != "" {
			redirectWithError(w, r, redirectURI, idpError, idpDesc)
			return
		}

		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("idp_error: "+idpError+" "+idpDesc))
		return
	}

	state := strings.TrimSpace(r.Form.Get("state"))
	code := strings.TrimSpace(r.Form.Get("code"))
	userPayload := strings.TrimSpace(r.Form.Get("user"))

	if state == "" {
		log.Warn("missing state")
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("state required"))
		return
	}

	if code == "" {
		log.Warn("missing code")
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("code required"))
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
	result, err := c.service.Callback(ctx, svc.CallbackRequest{
		Provider:    provider,
		State:       state,
		Code:        code,
		BaseURL:     baseURL,
		UserPayload: userPayload,
	})

	if err != nil {
		log.Error("callback failed",
			logger.String("provider", provider),
			logger.Err(err),
		)

		// Try to redirect with error to the client app (best UX)
		if redirectURI := c.extractRedirectURI(state); redirectURI != "" {
			errorCode, errorDesc := mapCallbackError(err)
			log.Info("redirecting with error",
				logger.String("error_code", errorCode),
			)
			redirectWithError(w, r, redirectURI, errorCode, errorDesc)
			return
		}

		// Fallback: JSON response (redirect_uri not extractable, e.g. invalid state)
		switch {
		case errors.Is(err, svc.ErrCallbackMissingState):
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("state required"))
		case errors.Is(err, svc.ErrCallbackMissingCode):
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("code required"))
		case errors.Is(err, svc.ErrCallbackInvalidState):
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invalid state"))
		case errors.Is(err, svc.ErrCallbackProviderMismatch):
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("provider mismatch"))
		case errors.Is(err, svc.ErrCallbackProviderUnknown), errors.Is(err, svc.ErrCallbackProviderDisabled):
			httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("provider not enabled"))
		case errors.Is(err, svc.ErrCallbackOIDCExchangeFailed):
			httperrors.WriteError(w, httperrors.ErrInternalServerError.WithDetail("code exchange failed"))
		case errors.Is(err, svc.ErrCallbackIDTokenInvalid):
			httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail("id_token invalid"))
		case errors.Is(err, svc.ErrCallbackEmailMissing):
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("email missing"))
		case errors.Is(err, svc.ErrCallbackProvisionFailed):
			httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("user provisioning failed"))
		case errors.Is(err, svc.ErrCallbackTokenIssueFailed):
			httperrors.WriteError(w, httperrors.ErrInternalServerError.WithDetail("token issuance failed"))
		default:
			httperrors.WriteError(w, httperrors.ErrInternalServerError)
		}
		return
	}

	// Set anti-cache headers
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// Redirect or JSON response
	if result.RedirectURL != "" {
		http.Redirect(w, r, result.RedirectURL, http.StatusFound)
		log.Debug("redirecting to client",
			logger.String("provider", provider),
		)
		return
	}

	// JSON response
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result.JSONResponse)

	log.Debug("callback completed",
		logger.String("provider", provider),
	)
}

// extractRedirectURI tries to parse the state JWT to extract the redirect_uri.
// Returns empty string if state is empty or parsing fails.
func (c *CallbackController) extractRedirectURI(state string) string {
	if state == "" || c.stateSigner == nil {
		return ""
	}
	claims, err := c.stateSigner.ParseState(state)
	if err != nil || claims == nil {
		return ""
	}
	return claims.RedirectURI
}

// mapCallbackError maps a service error to OAuth2-style error code and description.
func mapCallbackError(err error) (code, description string) {
	switch {
	case errors.Is(err, svc.ErrCallbackProvisionFailed):
		return "temporarily_unavailable", "The service is temporarily unavailable. Please try again later."
	case errors.Is(err, svc.ErrCallbackTokenIssueFailed):
		return "server_error", "Failed to complete authentication. Please try again."
	case errors.Is(err, svc.ErrCallbackProviderDisabled), errors.Is(err, svc.ErrCallbackProviderUnknown):
		return "unauthorized_client", "This login provider is not enabled."
	case errors.Is(err, svc.ErrCallbackOIDCExchangeFailed):
		return "server_error", "Failed to exchange authorization code. Please try again."
	case errors.Is(err, svc.ErrCallbackIDTokenInvalid):
		return "server_error", "Identity verification failed."
	case errors.Is(err, svc.ErrCallbackEmailMissing):
		return "invalid_request", "Email address is required but was not provided by the identity provider."
	case errors.Is(err, svc.ErrCallbackInvalidState):
		return "invalid_request", "Invalid or expired login session. Please try again."
	case errors.Is(err, svc.ErrCallbackProviderMismatch):
		return "invalid_request", "Provider mismatch detected."
	case errors.Is(err, svc.ErrCallbackInvalidClient):
		return "unauthorized_client", "Invalid client configuration."
	case errors.Is(err, svc.ErrCallbackInvalidRedirect):
		return "invalid_request", "Invalid redirect URI."
	case errors.Is(err, svc.ErrCallbackProviderMisconfigured):
		return "server_error", "The login provider is misconfigured."
	default:
		return "server_error", "An unexpected error occurred. Please try again."
	}
}

// redirectWithError redirects the user to the client app with error parameters.
func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, errorCode, errorDesc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		// Fallback: if redirect URI is invalid, just write error
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	q := u.Query()
	q.Set("error", errorCode)
	if errorDesc != "" {
		q.Set("error_description", errorDesc)
	}
	u.RawQuery = q.Encode()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	http.Redirect(w, r, u.String(), http.StatusFound)
}
