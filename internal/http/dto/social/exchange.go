package social

import dtoa "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"

// ExchangeRequest is the request for POST /v2/auth/social/exchange.
type ExchangeRequest struct {
	Code     string `json:"code"`
	ClientID string `json:"client_id"`
	TenantID string `json:"tenant_id,omitempty"` // Optional for backwards compat
}

// ExchangePayload is the stored payload in cache for social login codes.
type ExchangePayload struct {
	ClientID   string             `json:"client_id"`
	TenantID   string             `json:"tenant_id"`
	TenantSlug string             `json:"tenant_slug"` // Added for hardened validation
	Provider   string             `json:"provider"`    // Added for hardened validation
	Response   dtoa.LoginResponse `json:"response"`
}
