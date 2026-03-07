package session

import "time"

// LoginRequest is the request for POST /v2/session/login.
type LoginRequest struct {
	TenantID string `json:"tenant_id"` // Optional if ClientID provided
	ClientID string `json:"client_id"` // Optional if TenantID provided
	Email    string `json:"email"`
	Password string `json:"password"`
}

// SessionPayload is the payload stored in cache for a session.
type SessionPayload struct {
	UserID   string    `json:"user_id"`
	TenantID string    `json:"tenant_id"`
	Expires  time.Time `json:"expires"`
}

// LoginConfig contains configuration for session login.
type LoginConfig struct {
	CookieName   string        // Cookie name (default: "sid")
	CookieDomain string        // Cookie domain
	SameSite     string        // SameSite policy ("Lax", "Strict", "None")
	Secure       bool          // Secure flag for cookie
	TTL          time.Duration // Session TTL (default: 24h)
}
