package admin

// AdminLoginRequest es el request para login de admin
type AdminLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// AdminLoginResult es la respuesta de login exitoso
type AdminLoginResult struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresIn    int       `json:"expires_in"`
	TokenType    string    `json:"token_type"`
	Admin        AdminInfo `json:"admin"`
}

// AdminInfo contiene información del admin autenticado
type AdminInfo struct {
	ID      string   `json:"id"`
	Email   string   `json:"email"`
	Type    string   `json:"type"` // "global" | "tenant"
	Tenants []string `json:"tenants,omitempty"`
}

// AdminRefreshRequest es el request para refresh de token
type AdminRefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}
