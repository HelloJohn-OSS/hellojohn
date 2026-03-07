package security

// CSRFResponse is the response for GET /v2/csrf.
type CSRFResponse struct {
	CSRFToken string `json:"csrf_token"`
}

// CSRFConfig contains configuration for CSRF token generation.
type CSRFConfig struct {
	CookieName string // Cookie name (default: "csrf_token")
	TTLSeconds int    // Token TTL in seconds (default: 1800 = 30 min)
	Secure     bool   // Set Secure flag on cookie (should be true in prod)
}
