// Package oauth contiene los services del dominio OAuth2/OIDC.
package oauth

import (
	"context"
	"errors"
	"time"
)

// TokenService handles OAuth2 token endpoint logic.
type TokenService interface {
	// ExchangeAuthorizationCode handles grant_type=authorization_code (PKCE)
	ExchangeAuthorizationCode(ctx context.Context, req AuthCodeRequest) (*TokenResponse, error)

	// ExchangeRefreshToken handles grant_type=refresh_token (rotation)
	ExchangeRefreshToken(ctx context.Context, req RefreshTokenRequest) (*TokenResponse, error)

	// ExchangeClientCredentials handles grant_type=client_credentials (M2M)
	ExchangeClientCredentials(ctx context.Context, req ClientCredentialsRequest) (*TokenResponse, error)
}

// AuthCodeRequest contains parameters for authorization_code grant.
type AuthCodeRequest struct {
	Code         string
	RedirectURI  string
	ClientID     string
	CodeVerifier string
	TenantSlug   string // Resolved from request headers/query
}

// RefreshTokenRequest contains parameters for refresh_token grant.
type RefreshTokenRequest struct {
	ClientID     string
	RefreshToken string
	TenantSlug   string
}

// ClientCredentialsRequest contains parameters for client_credentials grant.
type ClientCredentialsRequest struct {
	ClientID     string
	ClientSecret string
	Scope        string
	TenantSlug   string
}

// TokenResponse is the standard OAuth2 token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// Token endpoint errors (OAuth2 standard).
var (
	ErrTokenInvalidRequest       = errors.New("invalid_request")
	ErrTokenInvalidClient        = errors.New("invalid_client")
	ErrTokenInvalidGrant         = errors.New("invalid_grant")
	ErrTokenUnauthorizedClient   = errors.New("unauthorized_client")
	ErrTokenUnsupportedGrantType = errors.New("unsupported_grant_type")
	ErrTokenInvalidScope         = errors.New("invalid_scope")
	ErrTokenServerError          = errors.New("server_error")
	ErrTokenDBNotConfigured      = errors.New("db_not_configured")
)

// AuthCodePayload is the cached authorization code data.
type AuthCodePayload struct {
	UserID          string    `json:"user_id"`
	ClientID        string    `json:"client_id"`
	TenantID        string    `json:"tenant_id"` // Actually slug in V1
	RedirectURI     string    `json:"redirect_uri"`
	Scope           string    `json:"scope"`
	Nonce           string    `json:"nonce,omitempty"`
	CodeChallenge   string    `json:"code_challenge"`
	ChallengeMethod string    `json:"challenge_method"` // "S256"
	AMR             []string  `json:"amr,omitempty"`
	ExpiresAt       time.Time `json:"expires_at"`
}
