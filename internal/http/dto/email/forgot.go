package email

type ForgotRequest struct {
	Email string `json:"email"`
	// TurnstileToken es el token generado por el widget Cloudflare Turnstile en el frontend.
	// Requerido cuando bot protection está habilitado para password reset.
	TurnstileToken string `json:"turnstile_token,omitempty"`
	// RemoteIP es la IP del cliente, extraída en el controller (no se deserializa desde JSON).
	RemoteIP string `json:"-"`
}

type ForgotResponse struct {
	OK bool `json:"ok"`
}
