package repository

import (
	"context"
	"time"
)

// Tenant representa un arrendatario del sistema.
type Tenant struct {
	ID          string
	Slug        string
	Name        string
	DisplayName string
	Language    string // Idioma por defecto del tenant ("es", "en")
	Settings    TenantSettings
	CreatedBy   string // UUID of the admin who created this tenant (empty for legacy/seed tenants)
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// TenantSettings contiene la configuración de un tenant.
type TenantSettings struct {
	LogoURL                     string        `json:"logoUrl" yaml:"logoUrl"`
	BrandColor                  string        `json:"brandColor" yaml:"brandColor"`
	SecondaryColor              string        `json:"secondaryColor" yaml:"secondaryColor"`
	FaviconURL                  string        `json:"faviconUrl" yaml:"faviconUrl"`
	SessionLifetimeSeconds      int           `json:"sessionLifetimeSeconds" yaml:"sessionLifetimeSeconds"`
	RefreshTokenLifetimeSeconds int           `json:"refreshTokenLifetimeSeconds" yaml:"refreshTokenLifetimeSeconds"`
	MFAEnabled                  bool          `json:"mfaEnabled" yaml:"mfaEnabled"`
	SocialLoginEnabled          bool          `json:"social_login_enabled" yaml:"social_login_enabled"`
	CookiePolicy                *CookiePolicy `json:"cookiePolicy,omitempty" yaml:"cookiePolicy,omitempty"`
	// EmailProvider es el nuevo bloque multi-provider.
	// Precedencia: emailProvider > smtp(legacy) > globalProvider > envProvider.
	EmailProvider *EmailProviderSettings `json:"emailProvider,omitempty" yaml:"emailProvider,omitempty"`
	SMTP          *SMTPSettings          `json:"smtp,omitempty" yaml:"smtp,omitempty"`
	UserDB        *UserDBSettings        `json:"userDb,omitempty" yaml:"userDb,omitempty"`
	Cache         *CacheSettings         `json:"cache,omitempty" yaml:"cache,omitempty"`
	Security      *SecurityPolicy        `json:"security,omitempty" yaml:"security,omitempty"`
	UserFields    []UserFieldDefinition  `json:"userFields,omitempty" yaml:"userFields,omitempty"`
	Mailing       *MailingSettings       `json:"mailing,omitempty" yaml:"mailing,omitempty"`
	// IssuerMode configura cómo se construye el issuer/JWKS por tenant.
	IssuerMode         string                 `json:"issuerMode,omitempty" yaml:"issuerMode,omitempty"`
	IssuerOverride     string                 `json:"issuerOverride,omitempty" yaml:"issuerOverride,omitempty"`
	SocialProviders    *SocialConfig          `json:"socialProviders,omitempty" yaml:"socialProviders,omitempty"`
	ConsentPolicy      *ConsentPolicySettings `json:"consentPolicy,omitempty" yaml:"consentPolicy,omitempty"`
	Passwordless       *PasswordlessConfig    `json:"passwordless,omitempty" yaml:"passwordless,omitempty"`
	MFA                *MFAConfig             `json:"mfa,omitempty" yaml:"mfa,omitempty"`
	AuditRetentionDays int                    `json:"auditRetentionDays,omitempty" yaml:"auditRetentionDays,omitempty"` // 0 = no auto-purge
	Webhooks           []WebhookConfig        `json:"webhooks,omitempty" yaml:"webhooks,omitempty"`
	WebAuthn           WebAuthnConfig         `json:"webAuthn,omitempty" yaml:"webAuthn,omitempty"`
	// MigratingToDSN holds the plaintext target DSN in memory only (never persisted to yaml).
	// It is populated transiently during migration and cleared upon completion.
	// yaml:"-" ensures credentials never reach disk; use MigratingToDSNEnc for persisted state.
	MigratingToDSN string `json:"migratingToDsn,omitempty" yaml:"-"`
	// MigratingToDSNEnc is the encrypted form of the target DSN, persisted in tenant.yaml.
	MigratingToDSNEnc string `json:"-" yaml:"migratingToDsnEnc,omitempty"`

	// BotProtection configura la protección anti-bot por tenant.
	// Sobrescribe la configuración global cuando está habilitado.
	BotProtection *BotProtectionConfig `json:"botProtection,omitempty" yaml:"botProtection,omitempty"`
}

// BotProtectionConfig configura la protección anti-bot por tenant.
// Los campos *Key son solo para INPUT via API (yaml:"-").
// Los campos *Enc son los que se persisten encriptados (json:"-").
type BotProtectionConfig struct {
	Enabled  bool   `json:"enabled" yaml:"enabled"`
	Provider string `json:"provider" yaml:"provider"` // "turnstile" (único soportado por ahora)

	// Turnstile credentials
	// SiteKey es público — se expone al frontend via /v2/auth/config
	TurnstileSiteKey string `json:"turnstileSiteKey" yaml:"turnstileSiteKey"`
	// SecretKey: input-only, NUNCA se persiste en plain text
	TurnstileSecretKey string `json:"turnstileSecretKey,omitempty" yaml:"-"`
	// SecretKeyEnc: valor encriptado, es lo que se guarda en tenant.yaml
	TurnstileSecretEnc string `json:"-" yaml:"turnstileSecretEnc,omitempty"`

	// Scopes de protección (cada uno togglable por separado)
	ProtectLogin         bool `json:"protectLogin" yaml:"protectLogin"`
	ProtectRegistration  bool `json:"protectRegistration" yaml:"protectRegistration"`
	ProtectPasswordReset bool `json:"protectPasswordReset" yaml:"protectPasswordReset"`

	// Behavior
	// Appearance: "always" | "execute" | "interaction-only"
	// "execute" = Turnstile decide si es visible o no (recomendado)
	Appearance string `json:"appearance" yaml:"appearance"`
	// Theme: "light" | "dark" | "auto"
	Theme string `json:"theme" yaml:"theme"`
}

// MFAConfig contains tenant-level MFA overrides.
// Nil means "use global server config".
type MFAConfig struct {
	// TOTPIssuer overrides global MFA_TOTP_ISSUER.
	TOTPIssuer string `json:"totpIssuer,omitempty" yaml:"totpIssuer,omitempty"`
	// TOTPWindow overrides global MFA_TOTP_WINDOW (0 = use global).
	TOTPWindow int `json:"totpWindow,omitempty" yaml:"totpWindow,omitempty"`

	SMS      *TenantSMSConfig      `json:"sms,omitempty" yaml:"sms,omitempty"`
	Adaptive *TenantAdaptiveConfig `json:"adaptive,omitempty" yaml:"adaptive,omitempty"`
}

// WebAuthnConfig configura la Relying Party por tenant para FIDO2/passkeys.
type WebAuthnConfig struct {
	// RPID es el dominio del tenant sin esquema ni puerto (ej: "app.acme.com").
	RPID string `json:"rpid,omitempty" yaml:"rpid,omitempty"`
	// RPOrigins son los origins permitidos para la ceremonia (ej: "https://app.acme.com").
	RPOrigins []string `json:"rpOrigins,omitempty" yaml:"rpOrigins,omitempty"`
	// RPDisplayName es el texto visible para el autenticador.
	RPDisplayName string `json:"rpDisplayName,omitempty" yaml:"rpDisplayName,omitempty"`
}

// TenantSMSConfig configures tenant-specific SMS provider.
// Sensitive credentials follow plain+enc pattern and are never persisted in plain.
type TenantSMSConfig struct {
	Provider string `json:"provider,omitempty" yaml:"provider,omitempty"` // "twilio" | "vonage"

	// Twilio
	TwilioAccountSID    string `json:"twilioAccountSid,omitempty" yaml:"-"`
	TwilioAccountSIDEnc string `json:"-" yaml:"twilioAccountSidEnc,omitempty"`
	TwilioAuthToken     string `json:"twilioAuthToken,omitempty" yaml:"-"`
	TwilioAuthTokenEnc  string `json:"-" yaml:"twilioAuthTokenEnc,omitempty"`
	TwilioFrom          string `json:"twilioFrom,omitempty" yaml:"twilioFrom,omitempty"`

	// Vonage
	VonageAPIKey       string `json:"vonageApiKey,omitempty" yaml:"-"`
	VonageAPIKeyEnc    string `json:"-" yaml:"vonageApiKeyEnc,omitempty"`
	VonageAPISecret    string `json:"vonageApiSecret,omitempty" yaml:"-"`
	VonageAPISecretEnc string `json:"-" yaml:"vonageApiSecretEnc,omitempty"`
	VonageFrom         string `json:"vonageFrom,omitempty" yaml:"vonageFrom,omitempty"`
}

// TenantAdaptiveConfig configures adaptive MFA overrides at tenant level.
type TenantAdaptiveConfig struct {
	Enabled          *bool    `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Rules            []string `json:"rules,omitempty" yaml:"rules,omitempty"`
	FailureThreshold int      `json:"failureThreshold,omitempty" yaml:"failureThreshold,omitempty"`
	StateTTLHours    int      `json:"stateTtlHours,omitempty" yaml:"stateTtlHours,omitempty"`
}

// PasswordlessConfig configura los métodos de autenticación sin contraseña.
type PasswordlessConfig struct {
	MagicLink MagicLinkConfig `json:"magicLink" yaml:"magicLink"`
	OTP       OTPConfig       `json:"otp" yaml:"otp"`
}

// MagicLinkConfig configura el flujo de Magic Link.
type MagicLinkConfig struct {
	Enabled      bool `json:"enabled" yaml:"enabled"`
	TTLSeconds   int  `json:"ttlSeconds" yaml:"ttlSeconds"`     // Default: 900 (15 min)
	AutoRegister bool `json:"autoRegister" yaml:"autoRegister"` // Create user if not exists
}

// OTPConfig configura el flujo de OTP por email.
type OTPConfig struct {
	Enabled        bool `json:"enabled" yaml:"enabled"`
	TTLSeconds     int  `json:"ttlSeconds" yaml:"ttlSeconds"` // Default: 300 (5 min)
	Length         int  `json:"length" yaml:"length"`         // Default: 6
	AutoRegister   bool `json:"autoRegister" yaml:"autoRegister"`
	DailyMaxEmails int  `json:"dailyMaxEmails" yaml:"dailyMaxEmails"` // Default: 10
}

// CookiePolicy allows tenant-level overrides for session cookies.
type CookiePolicy struct {
	Domain   string `json:"domain,omitempty" yaml:"domain,omitempty"`
	SameSite string `json:"sameSite,omitempty" yaml:"sameSite,omitempty"` // Lax | Strict | None
	Secure   *bool  `json:"secure,omitempty" yaml:"secure,omitempty"`
}

// SMTPSettings configuración de email.
type SMTPSettings struct {
	Host        string `json:"host" yaml:"host"`
	Port        int    `json:"port" yaml:"port"`
	Username    string `json:"username" yaml:"username"`
	Password    string `json:"password,omitempty" yaml:"-"`    // Plain (no persiste)
	PasswordEnc string `json:"-" yaml:"passwordEnc,omitempty"` // Encrypted
	FromEmail   string `json:"fromEmail" yaml:"fromEmail"`
	UseTLS      bool   `json:"useTLS" yaml:"useTLS"`
}

// EmailProviderSettings configura el provider de email por tenant.
// Secretos plain se aceptan para write-only y se persisten solo como *Enc.
type EmailProviderSettings struct {
	Provider  string `json:"provider" yaml:"provider"` // smtp|resend|sendgrid|mailgun
	FromEmail string `json:"fromEmail" yaml:"fromEmail"`
	ReplyTo   string `json:"replyTo,omitempty" yaml:"replyTo,omitempty"`
	TimeoutMs int    `json:"timeoutMs,omitempty" yaml:"timeoutMs,omitempty"`

	APIKey    string `json:"apiKey,omitempty" yaml:"-"`
	APIKeyEnc string `json:"-" yaml:"apiKeyEnc,omitempty"`
	Domain    string `json:"domain,omitempty" yaml:"domain,omitempty"`
	Region    string `json:"region,omitempty" yaml:"region,omitempty"`

	SMTPHost        string `json:"smtpHost,omitempty" yaml:"smtpHost,omitempty"`
	SMTPPort        int    `json:"smtpPort,omitempty" yaml:"smtpPort,omitempty"`
	SMTPUsername    string `json:"smtpUsername,omitempty" yaml:"smtpUsername,omitempty"`
	SMTPPassword    string `json:"smtpPassword,omitempty" yaml:"-"`
	SMTPPasswordEnc string `json:"-" yaml:"smtpPasswordEnc,omitempty"`
	SMTPUseTLS      bool   `json:"smtpUseTLS,omitempty" yaml:"smtpUseTLS,omitempty"`
}

// UserDBSettings configuración de DB por tenant.
type UserDBSettings struct {
	Driver     string `json:"driver" yaml:"driver"`
	DSN        string `json:"dsn,omitempty" yaml:"-"`    // Plain (no persiste)
	DSNEnc     string `json:"-" yaml:"dsnEnc,omitempty"` // Encrypted
	Schema     string `json:"schema,omitempty" yaml:"schema,omitempty"`
	ManualMode bool   `json:"manualMode,omitempty" yaml:"manualMode,omitempty"`
}

// CacheSettings configuración de cache por tenant.
type CacheSettings struct {
	Enabled  bool   `json:"enabled" yaml:"enabled"`
	Driver   string `json:"driver" yaml:"driver"`
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port" yaml:"port"`
	Password string `json:"password,omitempty" yaml:"-"` // Plain (no persiste)
	PassEnc  string `json:"-" yaml:"passEnc,omitempty"`  // Encrypted
	DB       int    `json:"db" yaml:"db"`
	Prefix   string `json:"prefix" yaml:"prefix"`
}

// SecurityPolicy políticas de seguridad.
type SecurityPolicy struct {
	PasswordMinLength      int  `json:"passwordMinLength" yaml:"passwordMinLength"`
	RequireUppercase       bool `json:"requireUppercase" yaml:"requireUppercase"`
	RequireLowercase       bool `json:"requireLowercase" yaml:"requireLowercase"`
	RequireNumbers         bool `json:"requireNumbers" yaml:"requireNumbers"`
	RequireSpecialChars    bool `json:"requireSpecialChars" yaml:"requireSpecialChars"`
	MaxHistory             int  `json:"maxHistory" yaml:"maxHistory"`
	BreachDetection        bool `json:"breachDetection" yaml:"breachDetection"`
	MFARequired            bool `json:"mfaRequired" yaml:"mfaRequired"`
	MaxLoginAttempts       int  `json:"maxLoginAttempts" yaml:"maxLoginAttempts"`
	LockoutDurationMinutes int  `json:"lockoutDurationMinutes" yaml:"lockoutDurationMinutes"`
}

// UserFieldDefinition define un campo custom de usuario.
type UserFieldDefinition struct {
	Name        string `json:"name" yaml:"name"`
	Type        string `json:"type" yaml:"type"`
	Required    bool   `json:"required" yaml:"required"`
	Unique      bool   `json:"unique" yaml:"unique"`
	Indexed     bool   `json:"indexed" yaml:"indexed"`
	Description string `json:"description" yaml:"description"`
}

// MailingSettings configuración de templates de email.
type MailingSettings struct {
	// Templates organizados por idioma: map[lang]map[templateID]EmailTemplate
	// Ejemplo: Templates["es"]["verify_email"] = EmailTemplate{...}
	Templates map[string]map[string]EmailTemplate `json:"templates" yaml:"templates"`
}

// EmailTemplate un template de email.
type EmailTemplate struct {
	Subject string `json:"subject" yaml:"subject"`
	Body    string `json:"body" yaml:"body"`
}

// TenantRepository define operaciones sobre tenants (Control Plane).
// Este repositorio opera sobre la configuración global, no sobre datos de usuarios.
type TenantRepository interface {
	// List retorna todos los tenants.
	List(ctx context.Context) ([]Tenant, error)

	// GetBySlug busca un tenant por su slug.
	GetBySlug(ctx context.Context, slug string) (*Tenant, error)

	// GetByID busca un tenant por su UUID.
	GetByID(ctx context.Context, id string) (*Tenant, error)

	// Create crea un nuevo tenant.
	// Retorna ErrConflict si el slug ya existe.
	Create(ctx context.Context, tenant *Tenant) error

	// Update actualiza un tenant existente.
	Update(ctx context.Context, tenant *Tenant) error

	// Delete elimina un tenant y toda su configuración.
	// id es el UUID del tenant.
	Delete(ctx context.Context, id string) error

	// UpdateSettings actualiza solo los settings de un tenant.
	// id es el UUID del tenant. Cifra automáticamente campos sensibles.
	UpdateSettings(ctx context.Context, id string, settings *TenantSettings) error
}

// ConsentPolicySettings configuración de políticas de consentimiento.
type ConsentPolicySettings struct {
	ConsentMode                   string `json:"consent_mode" yaml:"consentMode"`                           // "per_scope" | "single"
	ExpirationDays                *int   `json:"expiration_days,omitempty" yaml:"expirationDays,omitempty"` // null = never expires
	RepromptDays                  *int   `json:"reprompt_days,omitempty" yaml:"repromptDays,omitempty"`     // null = never reprompt
	RememberScopeDecisions        bool   `json:"remember_scope_decisions" yaml:"rememberScopeDecisions"`
	ShowConsentScreen             bool   `json:"show_consent_screen" yaml:"showConsentScreen"`
	AllowSkipConsentForFirstParty bool   `json:"allow_skip_consent_for_first_party" yaml:"allowSkipConsentForFirstParty"`
}

// SocialConfig: habilitación/config de IdPs sociales.
type SocialConfig struct {
	// Google OAuth
	GoogleEnabled   bool   `json:"googleEnabled" yaml:"googleEnabled"`
	GoogleClient    string `json:"googleClient" yaml:"googleClient"`
	GoogleSecret    string `json:"googleSecret,omitempty" yaml:"-"`                            // Plain (input)
	GoogleSecretEnc string `json:"googleSecretEnc,omitempty" yaml:"googleSecretEnc,omitempty"` // Encrypted (persisted)

	// GitHub OAuth
	GitHubEnabled   bool   `json:"githubEnabled" yaml:"githubEnabled"`
	GitHubClient    string `json:"githubClient" yaml:"githubClient"`
	GitHubSecret    string `json:"githubSecret,omitempty" yaml:"-"`
	GitHubSecretEnc string `json:"githubSecretEnc,omitempty" yaml:"githubSecretEnc,omitempty"`

	// Facebook OAuth (Graph API v19+)
	FacebookEnabled   bool   `json:"facebookEnabled" yaml:"facebookEnabled"`
	FacebookClient    string `json:"facebookClient" yaml:"facebookClient"`
	FacebookSecret    string `json:"facebookSecret,omitempty" yaml:"-"`
	FacebookSecretEnc string `json:"facebookSecretEnc,omitempty" yaml:"facebookSecretEnc,omitempty"`

	// Discord OAuth
	DiscordEnabled   bool   `json:"discordEnabled" yaml:"discordEnabled"`
	DiscordClient    string `json:"discordClient" yaml:"discordClient"`
	DiscordSecret    string `json:"discordSecret,omitempty" yaml:"-"`
	DiscordSecretEnc string `json:"discordSecretEnc,omitempty" yaml:"discordSecretEnc,omitempty"`

	// Microsoft / Azure AD (OIDC)
	MicrosoftEnabled   bool   `json:"microsoftEnabled" yaml:"microsoftEnabled"`
	MicrosoftClient    string `json:"microsoftClient" yaml:"microsoftClient"`
	MicrosoftSecret    string `json:"microsoftSecret,omitempty" yaml:"-"`
	MicrosoftSecretEnc string `json:"microsoftSecretEnc,omitempty" yaml:"microsoftSecretEnc,omitempty"`
	MicrosoftTenant    string `json:"microsoftTenant" yaml:"microsoftTenant"` // Default "common"

	// LinkedIn (OIDC v2)
	LinkedInEnabled   bool   `json:"linkedinEnabled" yaml:"linkedinEnabled"`
	LinkedInClient    string `json:"linkedinClient" yaml:"linkedinClient"`
	LinkedInSecret    string `json:"linkedinSecret,omitempty" yaml:"-"`
	LinkedInSecretEnc string `json:"linkedinSecretEnc,omitempty" yaml:"linkedinSecretEnc,omitempty"`

	// Apple Sign In (OIDC + P8 JWT)
	AppleEnabled       bool   `json:"appleEnabled" yaml:"appleEnabled"`
	AppleClientID      string `json:"appleClient" yaml:"appleClient"`
	AppleTeamID        string `json:"appleTeamId" yaml:"appleTeamId"`
	AppleKeyID         string `json:"appleKeyId" yaml:"appleKeyId"`
	ApplePrivateKeyEnc string `json:"applePrivateKeyEnc,omitempty" yaml:"applePrivateKeyEnc,omitempty"` // P8 PEM

	// Generic OIDC (self-hosted: Keycloak, GitLab, etc.)
	CustomOIDCProviders []CustomOIDCConfig `json:"customOidcProviders,omitempty" yaml:"customOidcProviders,omitempty"`
}

// CustomOIDCConfig describes a tenant-defined generic OIDC provider.
type CustomOIDCConfig struct {
	Alias           string   `json:"alias" yaml:"alias"`               // Unique name (e.g. "corporate-sso")
	WellKnownURL    string   `json:"wellKnownUrl" yaml:"wellKnownUrl"` // Discovery endpoint
	ClientID        string   `json:"clientId" yaml:"clientId"`
	ClientSecretEnc string   `json:"clientSecretEnc,omitempty" yaml:"clientSecretEnc,omitempty"`
	Scopes          []string `json:"scopes,omitempty" yaml:"scopes,omitempty"` // Default: ["openid","email","profile"]
	Enabled         bool     `json:"enabled" yaml:"enabled"`
}
