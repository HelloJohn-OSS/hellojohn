// Package oauth - AuthorizeController handles GET /oauth2/authorize
package oauth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/oauth"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/oauth"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// AuthorizeController handles the OAuth2 authorization endpoint.
type AuthorizeController struct {
	service svc.AuthorizeService
}

// NewAuthorizeController creates the controller.
func NewAuthorizeController(s svc.AuthorizeService) *AuthorizeController {
	return &AuthorizeController{service: s}
}

// Authorize handles GET /oauth2/authorize.
// Implements: PKCE, session/bearer auth, MFA step-up, auth code issuance.
func (c *AuthorizeController) Authorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("AuthorizeController.Authorize"))

	// Method check
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		httperrors.WriteError(w, httperrors.New(http.StatusMethodNotAllowed, "method_not_allowed", "only GET is allowed"))
		return
	}

	// Set Vary headers for caching
	w.Header().Add("Vary", "Cookie")
	w.Header().Add("Vary", "Authorization")

	// Parse query params
	q := r.URL.Query()
	req := dto.AuthorizeRequest{
		ResponseType:        strings.TrimSpace(q.Get("response_type")),
		ClientID:            strings.TrimSpace(q.Get("client_id")),
		RedirectURI:         strings.TrimSpace(q.Get("redirect_uri")),
		Scope:               strings.TrimSpace(q.Get("scope")),
		State:               strings.TrimSpace(q.Get("state")),
		Nonce:               strings.TrimSpace(q.Get("nonce")),
		CodeChallenge:       strings.TrimSpace(q.Get("code_challenge")),
		CodeChallengeMethod: strings.TrimSpace(q.Get("code_challenge_method")),
		Prompt:              strings.TrimSpace(q.Get("prompt")),
	}

	log.Debug("authorize request",
		logger.ClientID(req.ClientID),
		logger.String("response_type", req.ResponseType),
		logger.String("scope", req.Scope))

	// Call service
	result, err := c.service.Authorize(ctx, r, req)
	if err != nil {
		// Errors before redirect validation → JSON error
		switch err {
		case svc.ErrMissingParams:
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("missing required parameters"))
		case svc.ErrInvalidScope:
			httperrors.WriteError(w, httperrors.ErrScopeNotAllowed.WithDetail("scope must include openid"))
		case svc.ErrPKCERequired:
			httperrors.WriteError(w, httperrors.ErrPKCERequired)
		case svc.ErrInvalidClient:
			httperrors.WriteError(w, httperrors.ErrClientNotFound)
		case svc.ErrInvalidRedirect:
			httperrors.WriteError(w, httperrors.ErrRedirectMismatch)
		case svc.ErrGrantNotAllowed:
			httperrors.WriteError(w, httperrors.New(http.StatusBadRequest, "unsupported_grant_type", "profile does not allow authorization_code"))
		default:
			log.Error("authorize failed", logger.Err(err))
			httperrors.WriteError(w, httperrors.ErrInternalServerError)
		}
		return
	}

	// Handle result
	switch result.Type {
	case dto.AuthResultSuccess:
		c.redirectSuccess(w, r, result)

	case dto.AuthResultNeedLogin:
		http.Redirect(w, r, result.LoginURL, http.StatusFound)

	case dto.AuthResultMFARequired:
		c.respondMFARequired(w, result.MFAToken)

	case dto.AuthResultError:
		c.redirectError(w, r, result)
	}
}

// redirectSuccess redirects with the auth code.
func (c *AuthorizeController) redirectSuccess(w http.ResponseWriter, r *http.Request, result dto.AuthResult) {
	loc := addQueryParam(result.RedirectURI, "code", result.Code)
	if result.State != "" {
		loc = addQueryParam(loc, "state", result.State)
	}
	http.Redirect(w, r, loc, http.StatusFound)
}

// redirectError redirects with error params.
func (c *AuthorizeController) redirectError(w http.ResponseWriter, r *http.Request, result dto.AuthResult) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	loc := addQueryParam(result.RedirectURI, "error", result.ErrorCode)
	if result.ErrorDescription != "" {
		loc = addQueryParam(loc, "error_description", result.ErrorDescription)
	}
	http.Redirect(w, r, loc, http.StatusFound)
}

// respondMFARequired sends JSON response for MFA step-up.
func (c *AuthorizeController) respondMFARequired(w http.ResponseWriter, mfaToken string) {
	resp := dto.MFARequiredResponse{
		Status:   "mfa_required",
		MFAToken: mfaToken,
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// addQueryParam appends a query parameter to a URL.
func addQueryParam(u, key, value string) string {
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	return u + sep + url.QueryEscape(key) + "=" + url.QueryEscape(value)
}
