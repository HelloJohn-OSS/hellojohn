package session

// SessionLogoutConfig contains configuration for cookie deletion during logout.
type SessionLogoutConfig struct {
	CookieName   string          // Cookie name (default: "sid")
	CookieDomain string          // Cookie domain
	SameSite     string          // SameSite policy ("Lax", "Strict", "None")
	Secure       bool            // Secure flag for cookie
	AllowedHosts map[string]bool // Allowed hosts for return_to redirect
}
