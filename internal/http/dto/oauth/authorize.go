// Package oauth contains DTOs for OAuth2/OIDC endpoints.
package oauth

import "time"

// AuthorizeRequest contains the parsed query params for GET /oauth2/authorize.
type AuthorizeRequest struct {
	ResponseType        string `json:"response_type"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	Prompt              string `json:"prompt"` // e.g. "none"
}

// AuthCodePayload is stored in cache when an auth code is issued.
// It's consumed by the token endpoint to exchange code for tokens.
type AuthCodePayload struct {
	UserID          string    `json:"user_id"`
	TenantID        string    `json:"tenant_id"`
	ClientID        string    `json:"client_id"`
	RedirectURI     string    `json:"redirect_uri"`
	Scope           string    `json:"scope"`
	Nonce           string    `json:"nonce"`
	CodeChallenge   string    `json:"code_challenge"`
	ChallengeMethod string    `json:"code_challenge_method"`
	AMR             []string  `json:"amr"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// MFAChallenge is stored in cache when MFA step-up is required.
type MFAChallenge struct {
	UserID   string   `json:"user_id"`
	TenantID string   `json:"tenant_id"`
	ClientID string   `json:"client_id"`
	AMRBase  []string `json:"amr_base"` // e.g. ["pwd"]
	Scope    []string `json:"scope"`
}

// MFARequiredResponse is the JSON response when MFA step-up is needed.
type MFARequiredResponse struct {
	Status   string `json:"status"`    // "mfa_required"
	MFAToken string `json:"mfa_token"` // Token to present the MFA challenge
}

// SessionPayload represents cached session data from cookie login.
// Stored in cache with key "sid:<hash(cookie_value)>".
type SessionPayload struct {
	UserID   string    `json:"user_id"`
	TenantID string    `json:"tenant_id"`
	Expires  time.Time `json:"expires"`
}

// AuthResultType indicates the outcome of the authorization request.
type AuthResultType int

const (
	// AuthResultSuccess - issue auth code and redirect
	AuthResultSuccess AuthResultType = iota
	// AuthResultNeedLogin - redirect to login UI
	AuthResultNeedLogin
	// AuthResultMFARequired - return JSON mfa_required
	AuthResultMFARequired
	// AuthResultError - redirect with error params
	AuthResultError
)

// AuthResult is the outcome from AuthorizeService.Authorize.
type AuthResult struct {
	Type AuthResultType

	// For Success
	Code  string
	State string

	// For NeedLogin
	LoginURL string

	// For MFARequired
	MFAToken string

	// For Error
	ErrorCode        string
	ErrorDescription string

	// Common
	RedirectURI string
}
