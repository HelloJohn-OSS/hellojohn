package auth

// LogoutRequest represents the request body for POST /v2/auth/logout
type LogoutRequest struct {
	// TenantID is optional; resolved from context if omitted.
	TenantID string `json:"tenant_id,omitempty"`
	// ClientID is required and must match the refresh token's client.
	ClientID string `json:"client_id,omitempty"`
	// RefreshToken is the token to revoke.
	RefreshToken string `json:"refresh_token,omitempty"`
	// SessionID is injected by the controller from the session cookie.
	SessionID string `json:"-"`
	// PostLogoutRedirectURI is validated against client.PostLogoutURIs.
	PostLogoutRedirectURI string `json:"post_logout_redirect_uri,omitempty"`
}

// LogoutResult represents the result for POST /v2/auth/logout.
type LogoutResult struct {
	// PostLogoutRedirectURI is returned only when it matches client.PostLogoutURIs.
	PostLogoutRedirectURI string `json:"post_logout_redirect_uri,omitempty"`
}

// LogoutAllRequest represents the request body for POST /v2/auth/logout-all
type LogoutAllRequest struct {
	// UserID is required - the user whose sessions will be revoked.
	UserID string `json:"user_id"`
	// ClientID is optional - if provided, only revoke tokens for this client.
	ClientID string `json:"client_id,omitempty"`
}
