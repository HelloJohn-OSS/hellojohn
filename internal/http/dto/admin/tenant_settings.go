package admin

// TenantSettingsResponse represents tenant settings in API responses.
// This DTO mirrors repository.TenantSettings but provides API stability.
// Uses camelCase for consistency with the domain model and frontend.
type TenantSettingsResponse struct {
	// Core Settings
	IssuerMode     string  `json:"issuerMode"`               // "path" | "subdomain" | "global"
	IssuerOverride *string `json:"issuerOverride,omitempty"` // Custom issuer URL

	// Session Configuration
	SessionLifetimeSeconds      int `json:"sessionLifetimeSeconds,omitempty"`
	RefreshTokenLifetimeSeconds int `json:"refreshTokenLifetimeSeconds,omitempty"`

	// Feature Flags
	MFAEnabled         bool `json:"mfaEnabled"`
	SocialLoginEnabled bool `json:"socialLoginEnabled"`

	// Infrastructure Settings
	UserDB        *UserDBSettings              `json:"userDb,omitempty"`
	SMTP          *SMTPSettings                `json:"smtp,omitempty"`
	EmailProvider *TenantEmailProviderResponse `json:"emailProvider,omitempty"`
	Cache         *CacheSettings               `json:"cache,omitempty"`
	Security      *SecuritySettings            `json:"security,omitempty"`
	Mailing       *MailingSettings             `json:"mailing,omitempty"`

	// Branding
	LogoURL        string `json:"logoUrl,omitempty"`
	BrandColor     string `json:"brandColor,omitempty"`
	SecondaryColor string `json:"secondaryColor,omitempty"`
	FaviconURL     string `json:"faviconUrl,omitempty"`

	// Social Providers
	SocialProviders *SocialProvidersConfig `json:"socialProviders,omitempty"`

	// Passwordless
	Passwordless *PasswordlessSettings `json:"passwordless,omitempty"`

	// Callback URL base for social login (from server BASE_URL)
	CallbackURLBase string `json:"callbackUrlBase,omitempty"`

	// Consent Policy
	ConsentPolicy *ConsentPolicyDTO `json:"consentPolicy,omitempty"`

	// Custom User Fields
	UserFields []UserFieldDefinition `json:"userFields,omitempty"`

	// Audit
	AuditRetentionDays int `json:"auditRetentionDays,omitempty"` // 0 = no auto-purge

	// Bot Protection
	BotProtection *BotProtectionSettings `json:"botProtection,omitempty"`
}

// UserDBSettings configures the tenant's user database.
type UserDBSettings struct {
	Driver string `json:"driver"`           // "postgres" | "mysql" | "mongo"
	DSN    string `json:"dsn,omitempty"`    // Plain DSN (only in requests)
	DSNEnc string `json:"dsnEnc,omitempty"` // Encrypted DSN (in responses)
	Schema string `json:"schema,omitempty"` // Database schema name
}

// SMTPSettings configures email sending for the tenant.
type SMTPSettings struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password,omitempty"`    // Plain password (only in requests)
	PasswordEnc string `json:"passwordEnc,omitempty"` // Encrypted password (in responses)
	FromEmail   string `json:"fromEmail"`
	UseTLS      bool   `json:"useTLS"`
}

// TenantEmailProviderRequest defines write-only tenant email provider payload.
type TenantEmailProviderRequest struct {
	Provider  string `json:"provider"`
	FromEmail string `json:"fromEmail"`
	ReplyTo   string `json:"replyTo,omitempty"`
	TimeoutMs int    `json:"timeoutMs,omitempty"`

	APIKey       string `json:"apiKey,omitempty"` // write-only
	Domain       string `json:"domain,omitempty"`
	Region       string `json:"region,omitempty"`
	SMTPHost     string `json:"smtpHost,omitempty"`
	SMTPPort     int    `json:"smtpPort,omitempty"`
	SMTPUsername string `json:"smtpUsername,omitempty"`
	SMTPPassword string `json:"smtpPassword,omitempty"` // write-only
	SMTPUseTLS   bool   `json:"smtpUseTLS,omitempty"`
}

// TenantEmailProviderResponse masks secret fields and only exposes configured flags.
type TenantEmailProviderResponse struct {
	Provider         string `json:"provider"`
	FromEmail        string `json:"fromEmail"`
	ReplyTo          string `json:"replyTo,omitempty"`
	TimeoutMs        int    `json:"timeoutMs,omitempty"`
	Domain           string `json:"domain,omitempty"`
	Region           string `json:"region,omitempty"`
	SMTPHost         string `json:"smtpHost,omitempty"`
	SMTPPort         int    `json:"smtpPort,omitempty"`
	SMTPUsername     string `json:"smtpUsername,omitempty"`
	SMTPUseTLS       bool   `json:"smtpUseTLS,omitempty"`
	APIKeyConfigured bool   `json:"apiKeyConfigured"`
}

// CacheSettings configures caching for the tenant.
type CacheSettings struct {
	Enabled  bool   `json:"enabled"`
	Driver   string `json:"driver"`             // "memory" | "redis"
	Host     string `json:"host,omitempty"`     // Redis host
	Port     int    `json:"port,omitempty"`     // Redis port
	Password string `json:"password,omitempty"` // Plain (only in requests)
	PassEnc  string `json:"passEnc,omitempty"`  // Encrypted (in responses)
	DB       int    `json:"db,omitempty"`       // Redis DB number
	Prefix   string `json:"prefix,omitempty"`   // Key prefix
}

// SecuritySettings defines security policies.
type SecuritySettings struct {
	PasswordMinLength      int  `json:"passwordMinLength,omitempty"`
	RequireUppercase       bool `json:"requireUppercase,omitempty"`
	RequireLowercase       bool `json:"requireLowercase,omitempty"`
	RequireNumbers         bool `json:"requireNumbers,omitempty"`
	RequireSpecialChars    bool `json:"requireSpecialChars,omitempty"`
	MaxHistory             int  `json:"maxHistory,omitempty"`
	BreachDetection        bool `json:"breachDetection,omitempty"`
	MFARequired            bool `json:"mfaRequired"`
	MaxLoginAttempts       int  `json:"maxLoginAttempts,omitempty"`
	LockoutDurationMinutes int  `json:"lockoutDurationMinutes,omitempty"`
}

// SocialProvidersConfig configures social login providers.
type SocialProvidersConfig struct {
	// Google OAuth
	GoogleEnabled   bool   `json:"googleEnabled"`
	GoogleClient    string `json:"googleClient,omitempty"`
	GoogleSecret    string `json:"googleSecret,omitempty"`    // Plain (only in requests)
	GoogleSecretEnc string `json:"googleSecretEnc,omitempty"` // Encrypted (in responses)

	// GitHub OAuth
	GitHubEnabled   bool   `json:"githubEnabled"`
	GitHubClient    string `json:"githubClient,omitempty"`
	GitHubSecret    string `json:"githubSecret,omitempty"`    // Plain (only in requests)
	GitHubSecretEnc string `json:"githubSecretEnc,omitempty"` // Encrypted (in responses)

	// Facebook OAuth
	FacebookEnabled   bool   `json:"facebookEnabled"`
	FacebookClient    string `json:"facebookClient,omitempty"`
	FacebookSecret    string `json:"facebookSecret,omitempty"`
	FacebookSecretEnc string `json:"facebookSecretEnc,omitempty"`

	// Discord OAuth
	DiscordEnabled   bool   `json:"discordEnabled"`
	DiscordClient    string `json:"discordClient,omitempty"`
	DiscordSecret    string `json:"discordSecret,omitempty"`
	DiscordSecretEnc string `json:"discordSecretEnc,omitempty"`

	// Microsoft / Azure AD
	MicrosoftEnabled   bool   `json:"microsoftEnabled"`
	MicrosoftClient    string `json:"microsoftClient,omitempty"`
	MicrosoftSecret    string `json:"microsoftSecret,omitempty"`
	MicrosoftSecretEnc string `json:"microsoftSecretEnc,omitempty"`
	MicrosoftTenant    string `json:"microsoftTenant,omitempty"` // Default "common"

	// LinkedIn (OIDC v2)
	LinkedInEnabled   bool   `json:"linkedinEnabled"`
	LinkedInClient    string `json:"linkedinClient,omitempty"`
	LinkedInSecret    string `json:"linkedinSecret,omitempty"`
	LinkedInSecretEnc string `json:"linkedinSecretEnc,omitempty"`

	// Apple Sign In
	AppleEnabled       bool   `json:"appleEnabled"`
	AppleClientID      string `json:"appleClient,omitempty"`
	AppleTeamID        string `json:"appleTeamId,omitempty"`
	AppleKeyID         string `json:"appleKeyId,omitempty"`
	ApplePrivateKey    string `json:"applePrivateKey,omitempty"`    // P8 PEM plain (only in requests)
	ApplePrivateKeyEnc string `json:"applePrivateKeyEnc,omitempty"` // Encrypted (in responses)

	// Custom OIDC Providers
	CustomOIDCProviders []CustomOIDCProviderDTO `json:"customOidcProviders,omitempty"`
}

// CustomOIDCProviderDTO represents a custom OIDC provider configuration.
type CustomOIDCProviderDTO struct {
	Alias           string   `json:"alias"`
	WellKnownURL    string   `json:"wellKnownUrl"`
	ClientID        string   `json:"clientId"`
	ClientSecret    string   `json:"clientSecret,omitempty"`    // Plain (only in requests)
	ClientSecretEnc string   `json:"clientSecretEnc,omitempty"` // Encrypted (in responses)
	Scopes          []string `json:"scopes,omitempty"`
	Enabled         bool     `json:"enabled"`
}

// UserFieldDefinition defines a custom user field.
type UserFieldDefinition struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // "string" | "number" | "boolean" | "date"
	Required    bool   `json:"required"`
	Unique      bool   `json:"unique"`
	Indexed     bool   `json:"indexed"`
	Description string `json:"description,omitempty"`
}

// MailingSettings represents email template configuration.
type MailingSettings struct {
	Templates map[string]EmailTemplateDTO `json:"templates"`
}

// EmailTemplateDTO represents a single email template.
type EmailTemplateDTO struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

// UpdateTenantSettingsRequest represents a partial update to tenant settings.
// All fields are optional to support partial updates.
// Uses camelCase for consistency with the domain model and frontend.
type UpdateTenantSettingsRequest struct {
	// Core Settings
	IssuerMode     *string `json:"issuerMode,omitempty"`
	IssuerOverride *string `json:"issuerOverride,omitempty"`

	// Session Configuration
	SessionLifetimeSeconds      *int `json:"sessionLifetimeSeconds,omitempty"`
	RefreshTokenLifetimeSeconds *int `json:"refreshTokenLifetimeSeconds,omitempty"`

	// Feature Flags
	MFAEnabled         *bool `json:"mfaEnabled,omitempty"`
	SocialLoginEnabled *bool `json:"socialLoginEnabled,omitempty"`

	// Infrastructure Settings
	UserDB        *UserDBSettings             `json:"userDb,omitempty"`
	SMTP          *SMTPSettings               `json:"smtp,omitempty"`
	EmailProvider *TenantEmailProviderRequest `json:"emailProvider,omitempty"`
	Cache         *CacheSettings              `json:"cache,omitempty"`
	Security      *SecuritySettings           `json:"security,omitempty"`
	Mailing       *MailingSettings            `json:"mailing,omitempty"`

	// Branding
	LogoURL        *string `json:"logoUrl,omitempty"`
	BrandColor     *string `json:"brandColor,omitempty"`
	SecondaryColor *string `json:"secondaryColor,omitempty"`
	FaviconURL     *string `json:"faviconUrl,omitempty"`

	// Social Providers
	SocialProviders *SocialProvidersConfig `json:"socialProviders,omitempty"`

	// Passwordless
	Passwordless *PasswordlessSettings `json:"passwordless,omitempty"`

	// Consent Policy
	ConsentPolicy *ConsentPolicyDTO `json:"consentPolicy,omitempty"`

	// Custom User Fields
	UserFields []UserFieldDefinition `json:"userFields,omitempty"`

	// Audit
	AuditRetentionDays *int `json:"auditRetentionDays,omitempty"` // 0 = no auto-purge

	// Bot Protection
	BotProtection *BotProtectionSettings `json:"botProtection,omitempty"`
}

// ConsentPolicyDTO represents consent policy configuration.
type ConsentPolicyDTO struct {
	ConsentMode                   string `json:"consent_mode"`              // "per_scope" | "single"
	ExpirationDays                *int   `json:"expiration_days,omitempty"` // null = never expires
	RepromptDays                  *int   `json:"reprompt_days,omitempty"`   // null = never reprompt
	RememberScopeDecisions        bool   `json:"remember_scope_decisions"`
	ShowConsentScreen             bool   `json:"show_consent_screen"`
	AllowSkipConsentForFirstParty bool   `json:"allow_skip_consent_for_first_party"`
}

// PasswordlessSettings represents passwordless toggle settings used by admin UI.
type PasswordlessSettings struct {
	Enabled          bool `json:"enabled"`
	OTPEnabled       bool `json:"otpEnabled"`
	MagicLinkEnabled bool `json:"magicLinkEnabled"`
}

// BotProtectionSettings configures per-tenant bot protection (e.g. Cloudflare Turnstile).
// The secret key is write-only: plain value accepted in requests, encrypted stored in responses.
type BotProtectionSettings struct {
	Enabled              bool   `json:"enabled"`
	Provider             string `json:"provider,omitempty"`           // "turnstile" (only supported)
	TurnstileSiteKey     string `json:"turnstileSiteKey,omitempty"`   // Public site key
	TurnstileSecretKey   string `json:"turnstileSecretKey,omitempty"` // Plain (only in requests, never returned)
	TurnstileSecretEnc   string `json:"turnstileSecretEnc,omitempty"` // Encrypted (in responses)
	ProtectLogin         bool   `json:"protectLogin"`
	ProtectRegistration  bool   `json:"protectRegistration"`
	ProtectPasswordReset bool   `json:"protectPasswordReset"`
	Appearance           string `json:"appearance,omitempty"` // "always" | "execute" | "interaction-only"
	Theme                string `json:"theme,omitempty"`      // "auto" | "light" | "dark"
}
