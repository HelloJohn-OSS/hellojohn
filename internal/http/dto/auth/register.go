package auth

// RegisterRequest represents the request body for POST /v2/auth/register
type RegisterRequest struct {
	// TenantID is required (unless FS-admin mode is enabled).
	TenantID string `json:"tenant_id"`
	// ClientID is required (unless FS-admin mode is enabled).
	ClientID string `json:"client_id"`
	// Email is required and must be a valid email format.
	Email string `json:"email"`
	// Password is required and subject to password policy.
	Password string `json:"password"`
	// CustomFields are optional user-defined fields.
	CustomFields map[string]any `json:"custom_fields,omitempty"`
	// TurnstileToken es el token generado por el widget Cloudflare Turnstile en el frontend.
	TurnstileToken string `json:"turnstile_token,omitempty"`
	// RemoteIP es la IP del cliente, extraída en el controller (no se deserializa desde JSON).
	RemoteIP string `json:"-"`
}

// RegisterResponse represents the response for a successful registration.
type RegisterResponse struct {
	UserID       string `json:"user_id,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// RegisterResult is the internal result from RegisterService.
type RegisterResult struct {
	UserID       string
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	// IsFSAdmin indicates if the user was registered as FS admin (no tenant).
	IsFSAdmin bool
}
