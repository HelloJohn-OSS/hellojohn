package auth

// ConfigRequest holds query params for GET /v2/auth/config
type ConfigRequest struct {
	ClientID string `json:"client_id"`
}

// CustomFieldSchema defines a custom field for the UI.
type CustomFieldSchema struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // "text", "number", "boolean"
	Label    string `json:"label"`
	Required bool   `json:"required"`
}

// ConfigResponse is the public config for frontend auth UI.
type ConfigResponse struct {
	TenantName      string              `json:"tenant_name"`
	TenantSlug      string              `json:"tenant_slug"`
	ClientName      string              `json:"client_name"`
	LogoURL         string              `json:"logo_url,omitempty"`
	PrimaryColor    string              `json:"primary_color,omitempty"`
	SocialProviders []string            `json:"social_providers"`
	PasswordEnabled bool                `json:"password_enabled"`
	Features        map[string]bool     `json:"features,omitempty"`
	CustomFields    []CustomFieldSchema `json:"custom_fields,omitempty"`

	// Email verification & password reset URLs
	RequireEmailVerification bool   `json:"require_email_verification,omitempty"`
	ResetPasswordURL         string `json:"reset_password_url,omitempty"`
	VerifyEmailURL           string `json:"verify_email_url,omitempty"`

	// BotProtection contiene la config pública (siteKey solamente, nunca secretKey).
	BotProtection *BotProtectionPublicConfig `json:"botProtection,omitempty"`
}

// BotProtectionPublicConfig es la información pública que se expone al frontend.
// NUNCA incluye el secret key.
type BotProtectionPublicConfig struct {
	Enabled              bool   `json:"enabled"`
	Provider             string `json:"provider"` // "turnstile"
	SiteKey              string `json:"siteKey"`  // Key pública del widget
	ProtectLogin         bool   `json:"protectLogin"`
	ProtectRegistration  bool   `json:"protectRegistration"`
	ProtectPasswordReset bool   `json:"protectPasswordReset"`
	Appearance           string `json:"appearance"` // "execute" | "always" | "interaction-only"
	Theme                string `json:"theme"`      // "light" | "dark" | "auto"
}

// ConfigResult is the internal result from ConfigService.
type ConfigResult struct {
	TenantName      string
	TenantSlug      string
	ClientName      string
	LogoURL         string
	PrimaryColor    string
	SocialProviders []string
	PasswordEnabled bool
	Features        map[string]bool
	CustomFields    []CustomFieldSchema

	RequireEmailVerification bool
	ResetPasswordURL         string
	VerifyEmailURL           string

	// BotProtection contiene la config pública de bot protection (solo siteKey, nunca secretKey).
	// Nil si la protección está deshabilitada para este tenant.
	BotProtection *BotProtectionPublicConfig
}

// PasswordPolicyResponse is the public payload for GET /v2/auth/password-policy.
type PasswordPolicyResponse struct {
	Configured       bool   `json:"configured"`
	Source           string `json:"source,omitempty"`
	TenantID         string `json:"tenant_id,omitempty"`
	MinLength        int    `json:"min_length"`
	MaxLength        int    `json:"max_length"`
	RequireUppercase bool   `json:"require_uppercase"`
	RequireLowercase bool   `json:"require_lowercase"`
	RequireNumbers   bool   `json:"require_numbers"`
	RequireSymbols   bool   `json:"require_symbols"`
	MaxHistory       int    `json:"max_history"`
	BreachDetection  bool   `json:"breach_detection"`
	CommonPassword   bool   `json:"common_password"`
	PersonalInfo     bool   `json:"personal_info"`
}

// PasswordPolicyResult is the internal service result for password policy.
type PasswordPolicyResult struct {
	Configured       bool
	Source           string
	TenantID         string
	MinLength        int
	MaxLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumbers   bool
	RequireSymbols   bool
	MaxHistory       int
	BreachDetection  bool
	CommonPassword   bool
	PersonalInfo     bool
}
