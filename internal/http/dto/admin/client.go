// Package admin contiene DTOs para endpoints administrativos.
package admin

// ClientRequest representa la entrada para crear o actualizar un client.
type ClientRequest struct {
	Name                     string   `json:"name"`
	ClientID                 string   `json:"client_id"`
	Type                     string   `json:"type"` // "public" | "confidential"
	AuthProfile              string   `json:"auth_profile,omitempty"`
	RedirectURIs             []string `json:"redirect_uris,omitempty"`
	AllowedOrigins           []string `json:"allowed_origins,omitempty"`
	Providers                []string `json:"providers,omitempty"`
	Scopes                   []string `json:"scopes,omitempty"`
	Secret                   string   `json:"secret,omitempty"`
	RequireEmailVerification bool     `json:"require_email_verification,omitempty"`
	ResetPasswordURL         string   `json:"reset_password_url,omitempty"`
	VerifyEmailURL           string   `json:"verify_email_url,omitempty"`

	// Campos adicionales para OAuth2/OIDC avanzado
	GrantTypes      []string `json:"grant_types,omitempty"`
	AccessTokenTTL  int      `json:"access_token_ttl,omitempty"`
	RefreshTokenTTL int      `json:"refresh_token_ttl,omitempty"`
	IDTokenTTL      int      `json:"id_token_ttl,omitempty"`
	PostLogoutURIs  []string `json:"post_logout_uris,omitempty"`
	Description     string   `json:"description,omitempty"`
}

// ClientResponse representa un client en la respuesta.
type ClientResponse struct {
	ID                       string   `json:"id"`
	Name                     string   `json:"name"`
	ClientID                 string   `json:"client_id"`
	Type                     string   `json:"type"`
	AuthProfile              string   `json:"auth_profile,omitempty"`
	RedirectURIs             []string `json:"redirect_uris,omitempty"`
	AllowedOrigins           []string `json:"allowed_origins,omitempty"`
	Providers                []string `json:"providers,omitempty"`
	Scopes                   []string `json:"scopes,omitempty"`
	SecretHash               string   `json:"secret_hash,omitempty"`
	Secret                   string   `json:"secret,omitempty"` // Solo se retorna al crear/rotar (plaintext)
	RequireEmailVerification bool     `json:"require_email_verification,omitempty"`
	ResetPasswordURL         string   `json:"reset_password_url,omitempty"`
	VerifyEmailURL           string   `json:"verify_email_url,omitempty"`
	CreatedAt                string   `json:"created_at,omitempty"`
	UpdatedAt                string   `json:"updated_at,omitempty"`

	// Campos adicionales para OAuth2/OIDC avanzado
	GrantTypes      []string `json:"grant_types,omitempty"`
	AccessTokenTTL  int      `json:"access_token_ttl,omitempty"`
	RefreshTokenTTL int      `json:"refresh_token_ttl,omitempty"`
	IDTokenTTL      int      `json:"id_token_ttl,omitempty"`
	PostLogoutURIs  []string `json:"post_logout_uris,omitempty"`
	Description     string   `json:"description,omitempty"`
}

// StatusResponse es una respuesta genérica de estado.
type StatusResponse struct {
	Status string `json:"status"`
}

// RevokeClientSecretResponse para POST /v2/admin/clients/{id}/revoke
type RevokeClientSecretResponse struct {
	ClientID  string `json:"client_id"`
	NewSecret string `json:"new_secret"`
	Message   string `json:"message"`
}
