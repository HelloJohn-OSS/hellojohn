// Package admin contiene DTOs para endpoints administrativos.
package admin

// ClaimResponse representa un claim custom en respuestas.
type ClaimResponse struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Description   string         `json:"description,omitempty"`
	Source        string         `json:"source"`
	Value         string         `json:"value"`
	AlwaysInclude bool           `json:"always_include"`
	Scopes        []string       `json:"scopes,omitempty"`
	Enabled       bool           `json:"enabled"`
	System        bool           `json:"system"`
	Required      bool           `json:"required"`
	ConfigData    map[string]any `json:"config,omitempty"`
	CreatedAt     string         `json:"created_at,omitempty"`
	UpdatedAt     string         `json:"updated_at,omitempty"`
}

// ClaimCreateRequest para crear claim.
type ClaimCreateRequest struct {
	Name          string         `json:"name"`
	Description   string         `json:"description,omitempty"`
	Source        string         `json:"source"`
	Value         string         `json:"value"`
	AlwaysInclude bool           `json:"always_include"`
	Scopes        []string       `json:"scopes,omitempty"`
	Enabled       bool           `json:"enabled"`
	Required      bool           `json:"required"`
	ConfigData    map[string]any `json:"config,omitempty"`
}

// ClaimUpdateRequest para actualizar claim.
type ClaimUpdateRequest struct {
	Description   *string        `json:"description,omitempty"`
	Source        *string        `json:"source,omitempty"`
	Value         *string        `json:"value,omitempty"`
	AlwaysInclude *bool          `json:"always_include,omitempty"`
	Scopes        []string       `json:"scopes,omitempty"`
	Enabled       *bool          `json:"enabled,omitempty"`
	Required      *bool          `json:"required,omitempty"`
	ConfigData    map[string]any `json:"config,omitempty"`
}

// StandardClaimResponse representa claim OIDC estándar.
type StandardClaimResponse struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Scope       string `json:"scope"`
}

// StandardClaimToggleRequest para habilitar/deshabilitar.
type StandardClaimToggleRequest struct {
	Enabled bool `json:"enabled"`
}

// ClaimsSettingsResponse para settings globales.
type ClaimsSettingsResponse struct {
	IncludeInAccessToken bool    `json:"include_in_access_token"`
	UseNamespacedClaims  bool    `json:"use_namespaced_claims"`
	NamespacePrefix      *string `json:"namespace_prefix,omitempty"`
}

// ClaimsSettingsUpdateRequest para PATCH settings.
type ClaimsSettingsUpdateRequest struct {
	IncludeInAccessToken *bool   `json:"include_in_access_token,omitempty"`
	UseNamespacedClaims  *bool   `json:"use_namespaced_claims,omitempty"`
	NamespacePrefix      *string `json:"namespace_prefix,omitempty"`
}

// ScopeMappingResponse para mapeo scope→claims.
type ScopeMappingResponse struct {
	Scope  string   `json:"scope"`
	Claims []string `json:"claims"`
}

// ClaimsConfigResponse respuesta completa GET /claims.
type ClaimsConfigResponse struct {
	StandardClaims []StandardClaimResponse `json:"standard_claims"`
	CustomClaims   []ClaimResponse         `json:"custom_claims"`
	ScopeMappings  []ScopeMappingResponse  `json:"scope_mappings"`
	Settings       ClaimsSettingsResponse  `json:"settings"`
}

// ClaimPlaygroundRequest contiene el entorno ficticio para evaluar Custom Claims en vivo.
type ClaimPlaygroundRequest struct {
	ResolverType string         `json:"resolver_type"` // "expression", "webhook_api", "static", "user_attribute"
	ConfigData   map[string]any `json:"config"`
	MockContext  struct {
		Email    string         `json:"email,omitempty"`
		Scopes   []string       `json:"scopes,omitempty"`
		Roles    []string       `json:"roles,omitempty"`
		UserMeta map[string]any `json:"user_meta,omitempty"`
	} `json:"mock_context"`
}

// ClaimPlaygroundResponse devuelve el veredicto del Engine AST local
type ClaimPlaygroundResponse struct {
	Success bool   `json:"success"`
	Result  any    `json:"result,omitempty"`
	Error   string `json:"error,omitempty"`
}
