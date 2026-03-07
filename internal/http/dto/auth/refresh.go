// Package auth contains DTOs for authentication endpoints.
package auth

// RefreshRequest represents the request body for POST /v2/auth/refresh
type RefreshRequest struct {
	// TenantID is optional; if omitted, resolved from context/headers.
	// Note: The refresh token itself is the source of truth for tenant.
	TenantID string `json:"tenant_id,omitempty"`
	// ClientID is required and must match the client that issued the original refresh token.
	ClientID string `json:"client_id"`
	// RefreshToken is the opaque refresh token to exchange for new tokens.
	RefreshToken string `json:"refresh_token"`
}

// RefreshResponse represents the response for a successful refresh.
type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"` // Always "Bearer"
	ExpiresIn    int64  `json:"expires_in"` // Seconds until access token expires
	RefreshToken string `json:"refresh_token"`
}

// RefreshResult is the internal result from RefreshService.
type RefreshResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
}
