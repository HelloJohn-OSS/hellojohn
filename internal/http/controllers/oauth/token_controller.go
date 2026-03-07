// Package oauth - TokenController handles POST /oauth2/token
package oauth

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"

	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"

	svc "github.com/dropDatabas3/hellojohn/internal/http/services/oauth"
)

// TokenController handles the OAuth2 token endpoint.
type TokenController struct {
	service svc.TokenService
}

// NewTokenController creates the controller.
func NewTokenController(s svc.TokenService) *TokenController {
	return &TokenController{service: s}
}

// Token handles POST /oauth2/token
// Implements: Authorization Code (PKCE), Refresh Token, Client Credentials grants.
func (c *TokenController) Token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("oauth.token"))

	// Method check
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		c.writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "Only POST method is allowed")
		return
	}

	// Limit body size (64KB for OAuth forms)
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)

	// Parse form
	if err := r.ParseForm(); err != nil {
		log.Warn("failed to parse form", logger.Err(err))
		c.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid form data")
		return
	}

	grantType := strings.TrimSpace(r.PostForm.Get("grant_type"))
	log = log.With(logger.String("grant_type", grantType))

	// Resolve tenant slug from request (header/query)
	tenantSlug := resolveTenantSlug(r)

	var resp *svc.TokenResponse
	var err error

	switch grantType {
	case "authorization_code":
		resp, err = c.handleAuthorizationCode(ctx, r, tenantSlug)

	case "refresh_token":
		resp, err = c.handleRefreshToken(ctx, r, tenantSlug)

	case "client_credentials":
		resp, err = c.handleClientCredentials(ctx, r, tenantSlug)

	default:
		c.writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "Grant type not supported")
		return
	}

	if err != nil {
		c.handleServiceError(w, err, ctx)
		return
	}

	// Success: write token response with no-cache headers
	c.writeTokenResponse(w, resp)
}

func (c *TokenController) handleAuthorizationCode(ctx context.Context, r *http.Request, tenantSlug string) (*svc.TokenResponse, error) {
	// Support client_secret_basic: extract client_id from Basic Auth header if present
	basicID, _ := extractBasicAuth(r)
	clientID := strings.TrimSpace(r.PostForm.Get("client_id"))
	if clientID == "" && basicID != "" {
		clientID = basicID
	}

	req := svc.AuthCodeRequest{
		Code:         strings.TrimSpace(r.PostForm.Get("code")),
		RedirectURI:  strings.TrimSpace(r.PostForm.Get("redirect_uri")),
		ClientID:     clientID,
		CodeVerifier: strings.TrimSpace(r.PostForm.Get("code_verifier")),
		TenantSlug:   tenantSlug,
	}
	return c.service.ExchangeAuthorizationCode(ctx, req)
}

func (c *TokenController) handleRefreshToken(ctx context.Context, r *http.Request, tenantSlug string) (*svc.TokenResponse, error) {
	// Support client_secret_basic: extract client_id from Basic Auth header if present
	basicID, _ := extractBasicAuth(r)
	clientID := strings.TrimSpace(r.PostForm.Get("client_id"))
	if clientID == "" && basicID != "" {
		clientID = basicID
	}

	req := svc.RefreshTokenRequest{
		ClientID:     clientID,
		RefreshToken: strings.TrimSpace(r.PostForm.Get("refresh_token")),
		TenantSlug:   tenantSlug,
	}
	return c.service.ExchangeRefreshToken(ctx, req)
}

func (c *TokenController) handleClientCredentials(ctx context.Context, r *http.Request, tenantSlug string) (*svc.TokenResponse, error) {
	// Support client_secret_basic (RFC 6749 §2.3.1):
	// Authorization: Basic base64(client_id:client_secret)
	// Falls back to client_secret_post (form body) if no Basic header.
	basicID, basicSecret := extractBasicAuth(r)

	clientID := strings.TrimSpace(r.PostForm.Get("client_id"))
	clientSecret := strings.TrimSpace(r.PostForm.Get("client_secret"))

	// Basic Auth takes precedence when present
	if basicID != "" {
		clientID = basicID
		clientSecret = basicSecret
	}

	req := svc.ClientCredentialsRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scope:        strings.TrimSpace(r.PostForm.Get("scope")),
		TenantSlug:   tenantSlug,
	}
	return c.service.ExchangeClientCredentials(ctx, req)
}

func (c *TokenController) handleServiceError(w http.ResponseWriter, err error, ctx context.Context) {
	log := logger.From(ctx)
	switch err {
	case svc.ErrTokenInvalidRequest:
		c.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Missing or invalid parameters")
	case svc.ErrTokenInvalidClient:
		c.writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
	case svc.ErrTokenInvalidGrant:
		c.writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Invalid or expired grant")
	case svc.ErrTokenUnauthorizedClient:
		c.writeOAuthError(w, http.StatusUnauthorized, "unauthorized_client", "Client not authorized for this grant type")
	case svc.ErrTokenUnsupportedGrantType:
		c.writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "Grant type not supported")
	case svc.ErrTokenInvalidScope:
		c.writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "Requested scope is invalid or not allowed")
	case svc.ErrTokenDBNotConfigured:
		c.writeOAuthError(w, http.StatusServiceUnavailable, "server_error", "Database not configured")
	default:
		log.Error("token endpoint error", logger.Err(err))
		c.writeOAuthError(w, http.StatusInternalServerError, "server_error", "An unexpected error occurred")
	}
}

func (c *TokenController) writeOAuthError(w http.ResponseWriter, status int, errorCode, description string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + errorCode + `","error_description":"` + description + `"}`))
}

func (c *TokenController) writeTokenResponse(w http.ResponseWriter, resp *svc.TokenResponse) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	// Build JSON manually for control over optional fields
	out := `{"access_token":"` + resp.AccessToken + `","token_type":"` + resp.TokenType + `","expires_in":` + itoa(resp.ExpiresIn)
	if resp.RefreshToken != "" {
		out += `,"refresh_token":"` + resp.RefreshToken + `"`
	}
	if resp.IDToken != "" {
		out += `,"id_token":"` + resp.IDToken + `"`
	}
	if resp.Scope != "" {
		out += `,"scope":"` + resp.Scope + `"`
	}
	out += `}`
	_, _ = w.Write([]byte(out))
}

// extractBasicAuth parses the Authorization: Basic header (RFC 6749 §2.3.1).
// Returns (clientID, clientSecret) or ("", "") if the header is missing/invalid.
func extractBasicAuth(r *http.Request) (string, string) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Basic ") {
		return "", ""
	}
	decoded, err := base64.StdEncoding.DecodeString(header[6:])
	if err != nil {
		return "", ""
	}
	// Format: client_id:client_secret
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func resolveTenantSlug(r *http.Request) string {
	// Check headers first (X-Tenant-Slug, X-Tenant-ID)
	if slug := r.Header.Get("X-Tenant-Slug"); slug != "" {
		return slug
	}
	if slug := r.Header.Get("X-Tenant-ID"); slug != "" {
		return slug
	}
	// Check query params
	if slug := r.URL.Query().Get("tenant"); slug != "" {
		return slug
	}
	if slug := r.URL.Query().Get("tenant_id"); slug != "" {
		return slug
	}
	// Default to "local" like V1
	return "local"
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte(n%10) + '0'
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// Dummy import to use httperrors package (for future use)
var _ = httperrors.ErrMethodNotAllowed
