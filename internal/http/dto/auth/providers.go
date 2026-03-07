package auth

// ProvidersRequest holds query params for GET /v2/auth/providers
type ProvidersRequest struct {
	TenantID    string `json:"tenant_id"`
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
}

// ProviderInfo represents a single provider in the discovery response.
type ProviderInfo struct {
	Name     string  `json:"name"`
	Enabled  bool    `json:"enabled"`
	Ready    bool    `json:"ready"`               // config correctly setup
	Popup    bool    `json:"popup"`               // hint for frontend (open in popup)
	StartURL *string `json:"start_url,omitempty"` // ready-to-use URL for social flow
	Reason   string  `json:"reason,omitempty"`    // only for config issues
}

// ProvidersResponse is the discovery response.
type ProvidersResponse struct {
	Providers []ProviderInfo `json:"providers"`
}

// ProvidersResult is the internal result from ProvidersService.
type ProvidersResult struct {
	Providers []ProviderInfo
}
