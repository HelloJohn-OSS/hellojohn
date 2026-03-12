package server

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/session"
	"github.com/dropDatabas3/hellojohn/internal/passwordpolicy"
)

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// GlobalConfig: single source of truth for all env-based runtime configuration.
//
// Every os.Getenv() call in the codebase should flow through here.
// Services receive their config via dependency injection, NEVER reading env directly.
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

const (
	defaultRefreshTTL       = 30 * 24 * time.Hour
	defaultSessionTTL       = 24 * time.Hour
	defaultSessionTokenTTL  = 5 * time.Minute
	defaultSocialLoginCode  = 60 * time.Second
	defaultSessionSameSite  = "Lax"
	defaultSessionCookieRaw = "sid"
	defaultKeyRotationGrace = 60
	defaultMFAOTPTimeout    = 5 * time.Minute
)

// SystemSMTPConfig contiene la configuración SMTP global del sistema.
// Se usa como fallback cuando un tenant no tiene SMTP configurado.
type SystemSMTPConfig struct {
	Host     string // SMTP_HOST
	Port     int    // SMTP_PORT (default 587)
	User     string // SMTP_USER
	Password string // SMTP_PASSWORD
	From     string // SMTP_FROM
}

// IsConfigured retorna true si el SMTP global tiene la configuración mínima.
func (c SystemSMTPConfig) IsConfigured() bool {
	return strings.TrimSpace(c.Host) != "" && strings.TrimSpace(c.From) != ""
}

// SystemEmailConfig define el provider global de email del sistema.
// Mantiene compatibilidad con SMTP_* y agrega providers API.
type SystemEmailConfig struct {
	Provider string // smtp|resend|sendgrid|mailgun

	FromEmail string // SYSTEM_EMAIL_FROM (fallback SMTP_FROM)
	ReplyTo   string // SYSTEM_EMAIL_REPLY_TO
	TimeoutMs int    // SYSTEM_EMAIL_TIMEOUT_MS (default 10000)

	ResendAPIKey   string // SYSTEM_RESEND_API_KEY
	SendGridAPIKey string // SYSTEM_SENDGRID_API_KEY
	SendGridDomain string // SYSTEM_SENDGRID_DOMAIN
	MailgunAPIKey  string // SYSTEM_MAILGUN_API_KEY
	MailgunDomain  string // SYSTEM_MAILGUN_DOMAIN
	MailgunRegion  string // SYSTEM_MAILGUN_REGION (us|eu)

	SMTP SystemSMTPConfig
}

func (c SystemEmailConfig) IsConfigured() bool {
	return strings.TrimSpace(c.Provider) != "" || c.SMTP.IsConfigured()
}

// Features contains runtime feature flags loaded from env.
type Features struct {
	// RefreshTokenReuseDetection enables refresh-token replay protection.
	// Where it's used:
	//   - /v2/auth/refresh (auth refresh service): detects reuse and revokes token family.
	//   - /oauth2/token grant_type=refresh_token (oauth token service): same behavior.
	RefreshTokenReuseDetection bool
	// SessionTokenEndpoint enables POST /v2/session/token (session cookie -> short-lived JWT).
	SessionTokenEndpoint bool
	// HostCookiePrefix enables automatic __Host- prefix for eligible session cookies.
	HostCookiePrefix bool
	// ClientProfiles enables auth_profile grant compatibility checks.
	ClientProfiles bool
}

// GlobalConfig centralizes ALL env-based runtime configuration.
type GlobalConfig struct {
	// â”€â”€â”€ System â”€â”€â”€
	AppEnv      string   // dev | staging | prod
	BaseURL     string   // Base URL for issuer, email links, UI fallback
	FSRoot      string   // Control plane FS root
	CORSOrigins []string // CORS allowed origins

	// â”€â”€â”€ Auth / Tokens â”€â”€â”€
	RefreshTTL          time.Duration
	SessionTokenTTL     time.Duration
	SessionTokenEnabled bool
	OAuthAllowBearer    bool
	OAuthCookieName     string
	SocialLoginCodeTTL  time.Duration
	AutoLogin           bool // Auto-login after registration
	FSAdminEnabled      bool // Allow FS-admin registration

	// â”€â”€â”€ Session â”€â”€â”€
	SessionLoginConfig  dto.LoginConfig
	SessionLogoutConfig dto.SessionLogoutConfig

	// â”€â”€â”€ MFA â”€â”€â”€
	MFATOTPWindow               int
	MFATOTPIssuer               string
	MFASMSProvider              string
	MFASMSPhoneField            string
	MFASMSOTPLength             int
	MFASMSOTPTTL                time.Duration
	MFASMSRateLimitHourly       int
	MFASMSTwilioAccountSID      string
	MFASMSTwilioAuthToken       string
	MFASMSTwilioFrom            string
	MFASMSVonageAPIKey          string
	MFASMSVonageAPISecret       string
	MFASMSVonageFrom            string
	MFAEmailOTPLength           int
	MFAEmailOTPTTL              time.Duration
	MFAEmailRateLimitHourly     int
	MFAEmailSubject             string
	MFAPreferredFactorField     string
	MFAAdaptiveEnabled          bool
	MFAAdaptiveRules            []string
	MFAAdaptiveFailureThreshold int
	MFAAdaptiveStateTTL         time.Duration

	// â”€â”€â”€ Admin â”€â”€â”€
	AdminEnforce bool              // Strict admin mode
	AdminSubs    []string          // Emergency admin user IDs
	SystemSMTP   SystemSMTPConfig  // Legacy SMTP global
	SystemEmail  SystemEmailConfig // Multi-provider global

	// â”€â”€â”€ UI â”€â”€â”€
	UIBaseURL string // Frontend base URL (OAuth consent, etc.)

	// â”€â”€â”€ Misc â”€â”€â”€
	KeyRotationGrace int64  // Key rotation grace seconds
	ServiceVersion   string // For /health endpoint
	ServiceCommit    string // For /health endpoint

	// â”€â”€â”€ Audit â”€â”€â”€
	AuditStdoutEnabled       bool
	AuditControlPlaneLogPath string
	AuditOverflowLogPath     string

	// â”€â”€â”€ Global DB (Control Plane) â”€â”€â”€
	GlobalControlPlaneDSN    string // DSN de la DB del Control Plane global
	GlobalControlPlaneDriver string // "pg" | "mysql" (default "pg")

	// Admin seeding — crea el primer admin si cp_admin está vacía al arrancar.
	// Solo aplica cuando GlobalControlPlaneDSN está configurada. No usar en prod con datos reales.
	AdminSeedEmail    string // ADMIN_SEED_EMAIL
	AdminSeedPassword string // ADMIN_SEED_PASSWORD

	// Global Data Plane (Shared DB con RLS)
	GlobalDataPlaneDSN          string // GLOBAL_DATA_PLANE_DSN
	GlobalDataPlaneMaxOpenConns int    // GLOBAL_DATA_PLANE_MAX_OPEN_CONNS (default 25)
	GlobalDataPlaneMaxIdleConns int    // GLOBAL_DATA_PLANE_MAX_IDLE_CONNS (default 5)

	// Password Policy fallback chain:
	// tenant > global control plane > env > default (OSS)
	// global control plane > env > default (Cloud admin auth)
	PasswordPolicyGlobalTenant string                     // PASSWORD_POLICY_GLOBAL_TENANT (default "system")
	PasswordPolicyEnv          *repository.SecurityPolicy // SECURITY_PASSWORD_POLICY_* (optional)

	// ─── Cloud Control Plane (EPIC_013) ───
	CloudOIDCIssuer       string // URL base del IdP HJ para cloud auth
	CloudOIDCClientID     string // Client ID del panel cloud en el IdP
	CloudOIDCClientSecret string // Client Secret del panel cloud
	CloudOIDCRedirectURI  string // Callback URL
	CloudAllowInsecure    bool   // Si true, permite URLs http:// al registrar (solo dev)

	// Cloud Proxy Rate Limiting (MIX-001-F3)
	CloudProxyRateLimitRead  int // Max GET/HEAD per minute per admin:instance (default 120)
	CloudProxyRateLimitWrite int // Max POST/PUT/PATCH/DELETE per minute per admin:instance (default 60)

	// ─── Crypto Master Keys (CONV-001: moved from wiring.go) ───
	SigningMasterKey   string // SIGNING_MASTER_KEY: 64-char hex, required
	SecretboxMasterKey string // SECRETBOX_MASTER_KEY (or EMAIL_MASTER_KEY legacy alias): base64

	// Rate Limiting
	RateLimitEnabled bool          // Enable in-memory rate limiter (default true)
	RateLimitMax     int           // Max requests per window per key (default 10)
	RateLimitWindow  time.Duration // Rate limit window duration (default 1 minute)

	// â”€â”€â”€	// ─── Feature Flags ───
	Features Features
	// ─── Stripe (cloud billing) ───
	StripeSecretKey     string // STRIPE_SECRET_KEY
	StripeWebhookSecret string // STRIPE_WEBHOOK_SECRET
	StripePriceStarter  string // STRIPE_PRICE_STARTER
	StripePricePro      string // STRIPE_PRICE_PRO

	// ─── Bot Protection (Global Default) ───
	BotProtectionEnabled    bool   // BOT_PROTECTION_ENABLED
	BotProtectionProvider   string // BOT_PROTECTION_PROVIDER (default "turnstile")
	TurnstileSiteKey        string // TURNSTILE_SITE_KEY — public, se puede exponer al frontend
	TurnstileSecretKey      string // TURNSTILE_SECRET_KEY — NEVER expose
	BotProtectLogin         bool   // BOT_PROTECT_LOGIN (default true si enabled)
	BotProtectRegistration  bool   // BOT_PROTECT_REGISTRATION (default true si enabled)
	BotProtectPasswordReset bool   // BOT_PROTECT_PASSWORD_RESET (default false)
}

// LoadGlobalConfig resolves ALL env-based config for the runtime.
// This is the ONLY function that should call os.Getenv (besides main.go for critical keys).
func LoadGlobalConfig() GlobalConfig {
	features := loadFeatures()

	// â”€â”€â”€ System â”€â”€â”€
	appEnv := getenvStringDefault("APP_ENV", "dev")

	baseURL := getenvStringFirst([]string{"BASE_URL", "V2_BASE_URL"}, "http://localhost:8080")
	baseURL = strings.TrimRight(baseURL, "/")

	fsRoot := getenvStringFirst([]string{"FS_ROOT", "CONTROL_PLANE_FS_ROOT"}, "data")

	corsOrigins := parseCSV(getenvStringFirst([]string{
		"CORS_ORIGINS", "CORS_ALLOWED_ORIGINS", "SERVER_CORS_ALLOWED_ORIGINS",
	}, "http://localhost:3000"))

	// â”€â”€â”€ Auth / Tokens â”€â”€â”€
	refreshTTL := getenvDurationFirst([]string{"REFRESH_TTL", "REFRESH_TOKEN_TTL", "JWT_REFRESH_TTL"}, defaultRefreshTTL)
	sessionTokenTTL := getenvDurationFirst([]string{"SESSION_TOKEN_TTL", "AUTH_SESSION_TOKEN_TTL"}, defaultSessionTokenTTL)
	socialLoginCodeTTL := getenvDurationDefault("SOCIAL_LOGIN_CODE_TTL", defaultSocialLoginCode)
	autoLogin := getenvBoolDefault("REGISTER_AUTO_LOGIN", true)
	fsAdminEnabled := getenvBoolDefault("FS_ADMIN_ENABLE", false)

	// â”€â”€â”€ Session Cookie â”€â”€â”€
	sessionSecure := getenvBoolFirst([]string{"SESSION_SECURE", "AUTH_SESSION_SECURE"}, inferCookieSecure(baseURL, appEnv))
	sessionSameSite := normalizeSameSite(getenvStringFirst([]string{"SESSION_SAMESITE", "AUTH_SESSION_SAMESITE"}, defaultSessionSameSite))
	sessionDomain := strings.TrimSpace(getenvStringFirst([]string{"SESSION_DOMAIN", "AUTH_SESSION_DOMAIN"}, ""))
	sessionTTL := getenvDurationFirst([]string{"SESSION_TTL", "AUTH_SESSION_TTL"}, defaultSessionTTL)
	useHostPrefix := features.HostCookiePrefix

	sessionCookieName := normalizeSessionCookieName(
		getenvStringFirst([]string{"SESSION_COOKIE", "AUTH_SESSION_COOKIE_NAME"}, ""),
		sessionSecure,
		sessionDomain,
		useHostPrefix,
	)

	oauthCookieName := strings.TrimSpace(os.Getenv("OAUTH_COOKIE_NAME"))
	if oauthCookieName == "" {
		oauthCookieName = sessionCookieName
	}

	oauthAllowBearer := getenvBoolFirst([]string{"OAUTH_ALLOW_BEARER", "AUTH_ALLOW_BEARER_SESSION"}, false)

	loginConfig := dto.LoginConfig{
		CookieName:   sessionCookieName,
		CookieDomain: sessionDomain,
		SameSite:     sessionSameSite,
		Secure:       sessionSecure,
		TTL:          sessionTTL,
	}
	logoutConfig := dto.SessionLogoutConfig{
		CookieName:   sessionCookieName,
		CookieDomain: sessionDomain,
		SameSite:     sessionSameSite,
		Secure:       sessionSecure,
	}

	// â”€â”€â”€ MFA â”€â”€â”€
	mfaWindow := getenvIntDefault("MFA_TOTP_WINDOW", 1)
	if mfaWindow < 0 || mfaWindow > 3 {
		mfaWindow = 1
	}
	mfaIssuer := getenvStringDefault("MFA_TOTP_ISSUER", "HelloJohn")
	mfaSMSProvider := getenvStringDefault("MFA_SMS_PROVIDER", "twilio")
	mfaSMSPhoneField := getenvStringDefault("MFA_SMS_PHONE_FIELD", "phone")
	mfaSMSOTPLength := getenvIntDefault("MFA_SMS_OTP_LENGTH", 6)
	if mfaSMSOTPLength < 4 || mfaSMSOTPLength > 10 {
		mfaSMSOTPLength = 6
	}
	mfaSMSOTPTTL := getenvDurationDefault("MFA_SMS_OTP_TTL", defaultMFAOTPTimeout)
	if mfaSMSOTPTTL <= 0 {
		mfaSMSOTPTTL = defaultMFAOTPTimeout
	}
	mfaSMSRateLimitHourly := getenvIntDefault("MFA_SMS_RATE_LIMIT_HOURLY", 5)
	if mfaSMSRateLimitHourly <= 0 {
		mfaSMSRateLimitHourly = 5
	}
	mfaSMSTwilioAccountSID := getenvStringDefault("MFA_SMS_TWILIO_ACCOUNT_SID", "")
	mfaSMSTwilioAuthToken := getenvStringDefault("MFA_SMS_TWILIO_AUTH_TOKEN", "")
	mfaSMSTwilioFrom := getenvStringDefault("MFA_SMS_TWILIO_FROM", "")
	mfaSMSVonageAPIKey := getenvStringDefault("MFA_SMS_VONAGE_API_KEY", "")
	mfaSMSVonageAPISecret := getenvStringDefault("MFA_SMS_VONAGE_API_SECRET", "")
	mfaSMSVonageFrom := getenvStringDefault("MFA_SMS_VONAGE_FROM", "")
	mfaEmailOTPLength := getenvIntDefault("MFA_EMAIL_OTP_LENGTH", 6)
	if mfaEmailOTPLength < 4 || mfaEmailOTPLength > 10 {
		mfaEmailOTPLength = 6
	}
	mfaEmailOTPTTL := getenvDurationDefault("MFA_EMAIL_OTP_TTL", defaultMFAOTPTimeout)
	if mfaEmailOTPTTL <= 0 {
		mfaEmailOTPTTL = defaultMFAOTPTimeout
	}
	mfaEmailRateLimitHourly := getenvIntDefault("MFA_EMAIL_RATE_LIMIT_HOURLY", 5)
	if mfaEmailRateLimitHourly <= 0 {
		mfaEmailRateLimitHourly = 5
	}
	mfaEmailSubject := getenvStringDefault("MFA_EMAIL_SUBJECT", "Your verification code")
	mfaPreferredFactorField := getenvStringDefault("MFA_PREFERRED_FACTOR_FIELD", "mfa_preferred_factor")
	mfaAdaptiveEnabled := getenvBoolDefault("MFA_ADAPTIVE_ENABLED", false)
	mfaAdaptiveRules := parseCSV(getenvStringDefault("MFA_ADAPTIVE_RULES", "ip_change,ua_change,failed_attempts"))
	mfaAdaptiveFailureThreshold := getenvIntDefault("MFA_ADAPTIVE_FAILURE_THRESHOLD", 5)
	if mfaAdaptiveFailureThreshold <= 0 {
		mfaAdaptiveFailureThreshold = 5
	}
	mfaAdaptiveStateTTL := getenvDurationDefault("MFA_ADAPTIVE_STATE_TTL", 720*time.Hour)
	if mfaAdaptiveStateTTL <= 0 {
		mfaAdaptiveStateTTL = 720 * time.Hour
	}

	// â”€â”€â”€ Admin â”€â”€â”€
	adminEnforce := getenvBoolDefault("ADMIN_ENFORCE", false)
	adminSubs := parseCSV(getenvStringDefault("ADMIN_SUBS", ""))

	// System SMTP (Global Fallback)
	systemSMTPHost := strings.TrimSpace(os.Getenv("SMTP_HOST"))
	systemSMTPPort := getenvIntDefault("SMTP_PORT", 587)
	if systemSMTPPort <= 0 {
		systemSMTPPort = 587
	}
	systemSMTPUser := getenvStringFirst([]string{"SMTP_USER", "SMTP_USERNAME"}, "")
	systemSMTPPassword := strings.TrimSpace(os.Getenv("SMTP_PASSWORD"))
	systemSMTPFrom := strings.TrimSpace(os.Getenv("SMTP_FROM"))

	// System Email Provider (backward-first + additive).
	systemEmailProvider := strings.ToLower(strings.TrimSpace(os.Getenv("SYSTEM_EMAIL_PROVIDER")))
	if systemEmailProvider == "" && systemSMTPHost != "" {
		systemEmailProvider = "smtp"
	}
	systemEmailFrom := strings.TrimSpace(os.Getenv("SYSTEM_EMAIL_FROM"))
	if systemEmailFrom == "" {
		systemEmailFrom = systemSMTPFrom
	}
	systemEmailReplyTo := strings.TrimSpace(os.Getenv("SYSTEM_EMAIL_REPLY_TO"))
	systemEmailTimeoutMs := getenvIntDefault("SYSTEM_EMAIL_TIMEOUT_MS", 10000)
	if systemEmailTimeoutMs <= 0 {
		systemEmailTimeoutMs = 10000
	}
	systemResendAPIKey := strings.TrimSpace(os.Getenv("SYSTEM_RESEND_API_KEY"))
	systemSendGridAPIKey := strings.TrimSpace(os.Getenv("SYSTEM_SENDGRID_API_KEY"))
	systemSendGridDomain := strings.TrimSpace(os.Getenv("SYSTEM_SENDGRID_DOMAIN"))
	systemMailgunAPIKey := strings.TrimSpace(os.Getenv("SYSTEM_MAILGUN_API_KEY"))
	systemMailgunDomain := strings.TrimSpace(os.Getenv("SYSTEM_MAILGUN_DOMAIN"))
	systemMailgunRegion := strings.ToLower(strings.TrimSpace(os.Getenv("SYSTEM_MAILGUN_REGION")))
	if systemMailgunRegion == "" {
		systemMailgunRegion = "us"
	}

	// â”€â”€â”€ UI â”€â”€â”€
	uiBaseURL := getenvStringFirst([]string{"UI_BASE_URL", "FRONTEND_URL"}, "http://localhost:3000")
	uiBaseURL = strings.TrimRight(uiBaseURL, "/")

	// â”€â”€â”€ Misc â”€â”€â”€
	keyRotationGrace := int64(getenvIntDefault("KEY_ROTATION_GRACE", defaultKeyRotationGrace))
	// Legacy alias
	if v := strings.TrimSpace(os.Getenv("KEY_ROTATION_GRACE_SECONDS")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			keyRotationGrace = n
		}
	}

	// â”€â”€â”€ Audit â”€â”€â”€
	auditStdoutDefault := strings.EqualFold(appEnv, "dev") || strings.EqualFold(appEnv, "development") || strings.EqualFold(appEnv, "local") || strings.EqualFold(appEnv, "test")
	auditStdoutEnabled := getenvBoolDefault("AUDIT_STDOUT_ENABLED", auditStdoutDefault)
	auditControlPlaneLogPath := getenvStringDefault("AUDIT_CONTROLPLANE_LOG_PATH", "data/controlplane/audit.log")
	auditOverflowLogPath := getenvStringDefault("AUDIT_OVERFLOW_LOG_PATH", "data/controlplane/audit-overflow.log")

	// â”€â”€â”€ Global DB (Control Plane â€” EPIC 008) â”€â”€â”€
	globalControlPlaneDSN := getenvStringFirst([]string{"GLOBAL_CONTROL_PLANE_DSN", "GLOBAL_DB_DSN"}, "")
	globalControlPlaneDriver := getenvStringFirst([]string{"GLOBAL_CONTROL_PLANE_DRIVER", "GLOBAL_DB_DRIVER"}, "pg")
	adminSeedEmail := strings.TrimSpace(os.Getenv("ADMIN_SEED_EMAIL"))
	adminSeedPassword := strings.TrimSpace(os.Getenv("ADMIN_SEED_PASSWORD"))

	// Global Data Plane (EPIC GDP)
	gdpDSN := strings.TrimSpace(os.Getenv("GLOBAL_DATA_PLANE_DSN"))
	gdpMaxOpen := getenvIntDefault("GLOBAL_DATA_PLANE_MAX_OPEN_CONNS", 25)
	gdpMaxIdle := getenvIntDefault("GLOBAL_DATA_PLANE_MAX_IDLE_CONNS", 5)

	// Password Policy fallback chain
	passwordPolicyGlobalTenant := strings.TrimSpace(getenvStringDefault("PASSWORD_POLICY_GLOBAL_TENANT", "system"))
	passwordPolicyEnv := loadEnvPasswordPolicyFromEnv()

	// ─── Cloud Control Plane (EPIC_013) ───
	cloudOIDCIssuer := strings.TrimRight(strings.TrimSpace(os.Getenv("CLOUD_OIDC_ISSUER")), "/")
	cloudOIDCClientID := strings.TrimSpace(os.Getenv("CLOUD_OIDC_CLIENT_ID"))
	cloudOIDCClientSecret := strings.TrimSpace(os.Getenv("CLOUD_OIDC_CLIENT_SECRET"))
	cloudOIDCRedirectURI := strings.TrimSpace(os.Getenv("CLOUD_OIDC_REDIRECT_URI"))
	if cloudOIDCRedirectURI == "" {
		cloudOIDCRedirectURI = baseURL + "/v2/cloud/auth/callback"
	}
	cloudAllowInsecure := getenvBoolFirst([]string{"CLOUD_ALLOW_INSECURE", "CLOUD_ALLOW_HTTP"}, false)

	// Cloud Proxy Rate Limiting
	cloudProxyRateLimitRead := getenvIntDefault("CLOUD_PROXY_RATE_LIMIT_READ", 120)
	if cloudProxyRateLimitRead <= 0 {
		cloudProxyRateLimitRead = 120
	}
	cloudProxyRateLimitWrite := getenvIntDefault("CLOUD_PROXY_RATE_LIMIT_WRITE", 60)
	if cloudProxyRateLimitWrite <= 0 {
		cloudProxyRateLimitWrite = 60
	}

	// Rate Limiting
	rateLimitEnabled := getenvBoolDefault("RATE_LIMIT_ENABLED", true)
	// Admin panel pages make several parallel requests per route — keep per-path bucket.
	// Auth endpoints (login, register) share this same limiter but at IP-only scope,
	// so 100/min/IP is still brute-force safe while being comfortable for the admin UI.
	rateLimitMax := getenvIntDefault("RATE_LIMIT_MAX", 100)
	if rateLimitMax <= 0 {
		rateLimitMax = 100
	}
	rateLimitWindow := getenvDurationDefault("RATE_LIMIT_WINDOW", time.Minute)
	if rateLimitWindow <= 0 {
		rateLimitWindow = time.Minute
	}

	// ─── Crypto Master Keys (read here once; passed via Deps to avoid os.Getenv elsewhere) ───
	signingMasterKey := strings.TrimSpace(os.Getenv("SIGNING_MASTER_KEY"))
	secretboxMasterKey := strings.TrimSpace(os.Getenv("SECRETBOX_MASTER_KEY"))
	if secretboxMasterKey == "" {
		secretboxMasterKey = strings.TrimSpace(os.Getenv("EMAIL_MASTER_KEY")) // legacy alias
	}

	// ─── Stripe (cloud billing) ───
	stripeSecretKey := strings.TrimSpace(os.Getenv("STRIPE_SECRET_KEY"))
	stripeWebhookSecret := strings.TrimSpace(os.Getenv("STRIPE_WEBHOOK_SECRET"))
	stripePriceStarter := strings.TrimSpace(os.Getenv("STRIPE_PRICE_STARTER"))
	stripePricePro := strings.TrimSpace(os.Getenv("STRIPE_PRICE_PRO"))

	// ─── Bot Protection ───
	botProtectionEnabled := getenvBoolDefault("BOT_PROTECTION_ENABLED", false)
	botProtectionProvider := getenvStringDefault("BOT_PROTECTION_PROVIDER", "turnstile")
	turnstileSiteKey := strings.TrimSpace(os.Getenv("TURNSTILE_SITE_KEY"))
	turnstileSecretKey := strings.TrimSpace(os.Getenv("TURNSTILE_SECRET_KEY"))
	botProtectLogin := getenvBoolDefault("BOT_PROTECT_LOGIN", true)
	botProtectRegistration := getenvBoolDefault("BOT_PROTECT_REGISTRATION", true)
	botProtectPasswordReset := getenvBoolDefault("BOT_PROTECT_PASSWORD_RESET", false)

	return GlobalConfig{
		AppEnv:      appEnv,
		BaseURL:     baseURL,
		FSRoot:      fsRoot,
		CORSOrigins: corsOrigins,

		RefreshTTL:          refreshTTL,
		SessionTokenTTL:     sessionTokenTTL,
		SessionTokenEnabled: features.SessionTokenEndpoint,
		OAuthAllowBearer:    oauthAllowBearer,
		OAuthCookieName:     oauthCookieName,
		SocialLoginCodeTTL:  socialLoginCodeTTL,
		AutoLogin:           autoLogin,
		FSAdminEnabled:      fsAdminEnabled,

		SessionLoginConfig:  loginConfig,
		SessionLogoutConfig: logoutConfig,

		MFATOTPWindow:               mfaWindow,
		MFATOTPIssuer:               mfaIssuer,
		MFASMSProvider:              mfaSMSProvider,
		MFASMSPhoneField:            mfaSMSPhoneField,
		MFASMSOTPLength:             mfaSMSOTPLength,
		MFASMSOTPTTL:                mfaSMSOTPTTL,
		MFASMSRateLimitHourly:       mfaSMSRateLimitHourly,
		MFASMSTwilioAccountSID:      mfaSMSTwilioAccountSID,
		MFASMSTwilioAuthToken:       mfaSMSTwilioAuthToken,
		MFASMSTwilioFrom:            mfaSMSTwilioFrom,
		MFASMSVonageAPIKey:          mfaSMSVonageAPIKey,
		MFASMSVonageAPISecret:       mfaSMSVonageAPISecret,
		MFASMSVonageFrom:            mfaSMSVonageFrom,
		MFAEmailOTPLength:           mfaEmailOTPLength,
		MFAEmailOTPTTL:              mfaEmailOTPTTL,
		MFAEmailRateLimitHourly:     mfaEmailRateLimitHourly,
		MFAEmailSubject:             mfaEmailSubject,
		MFAPreferredFactorField:     mfaPreferredFactorField,
		MFAAdaptiveEnabled:          mfaAdaptiveEnabled,
		MFAAdaptiveRules:            mfaAdaptiveRules,
		MFAAdaptiveFailureThreshold: mfaAdaptiveFailureThreshold,
		MFAAdaptiveStateTTL:         mfaAdaptiveStateTTL,

		UIBaseURL: uiBaseURL,

		AdminEnforce: adminEnforce,
		AdminSubs:    adminSubs,
		SystemSMTP: SystemSMTPConfig{
			Host:     systemSMTPHost,
			Port:     systemSMTPPort,
			User:     systemSMTPUser,
			Password: systemSMTPPassword,
			From:     systemSMTPFrom,
		},
		SystemEmail: SystemEmailConfig{
			Provider:       systemEmailProvider,
			FromEmail:      systemEmailFrom,
			ReplyTo:        systemEmailReplyTo,
			TimeoutMs:      systemEmailTimeoutMs,
			ResendAPIKey:   systemResendAPIKey,
			SendGridAPIKey: systemSendGridAPIKey,
			SendGridDomain: systemSendGridDomain,
			MailgunAPIKey:  systemMailgunAPIKey,
			MailgunDomain:  systemMailgunDomain,
			MailgunRegion:  systemMailgunRegion,
			SMTP: SystemSMTPConfig{
				Host:     systemSMTPHost,
				Port:     systemSMTPPort,
				User:     systemSMTPUser,
				Password: systemSMTPPassword,
				From:     systemSMTPFrom,
			},
		},
		KeyRotationGrace:         keyRotationGrace,
		ServiceVersion:           strings.TrimSpace(os.Getenv("SERVICE_VERSION")),
		ServiceCommit:            strings.TrimSpace(os.Getenv("SERVICE_COMMIT")),
		AuditStdoutEnabled:       auditStdoutEnabled,
		AuditControlPlaneLogPath: auditControlPlaneLogPath,
		AuditOverflowLogPath:     auditOverflowLogPath,

		GlobalControlPlaneDSN:    globalControlPlaneDSN,
		GlobalControlPlaneDriver: globalControlPlaneDriver,
		AdminSeedEmail:           adminSeedEmail,
		AdminSeedPassword:        adminSeedPassword,

		CloudOIDCIssuer:       cloudOIDCIssuer,
		CloudOIDCClientID:     cloudOIDCClientID,
		CloudOIDCClientSecret: cloudOIDCClientSecret,
		CloudOIDCRedirectURI:  cloudOIDCRedirectURI,
		CloudAllowInsecure:    cloudAllowInsecure,

		CloudProxyRateLimitRead:  cloudProxyRateLimitRead,
		CloudProxyRateLimitWrite: cloudProxyRateLimitWrite,

		SigningMasterKey:   signingMasterKey,
		SecretboxMasterKey: secretboxMasterKey,

		GlobalDataPlaneDSN:          gdpDSN,
		GlobalDataPlaneMaxOpenConns: gdpMaxOpen,
		GlobalDataPlaneMaxIdleConns: gdpMaxIdle,
		PasswordPolicyGlobalTenant:  passwordPolicyGlobalTenant,
		PasswordPolicyEnv:           passwordPolicyEnv,

		RateLimitEnabled: rateLimitEnabled,
		RateLimitMax:     rateLimitMax,
		RateLimitWindow:  rateLimitWindow,

		Features: features,

		StripeSecretKey:     stripeSecretKey,
		StripeWebhookSecret: stripeWebhookSecret,
		StripePriceStarter:  stripePriceStarter,
		StripePricePro:      stripePricePro,

		// Bot Protection
		BotProtectionEnabled:    botProtectionEnabled,
		BotProtectionProvider:   botProtectionProvider,
		TurnstileSiteKey:        turnstileSiteKey,
		TurnstileSecretKey:      turnstileSecretKey,
		BotProtectLogin:         botProtectLogin,
		BotProtectRegistration:  botProtectRegistration,
		BotProtectPasswordReset: botProtectPasswordReset,
	}
}

// â”€â”€â”€ Feature Flags â”€â”€â”€

func loadFeatures() Features {
	return Features{
		// FEATURE_REFRESH_REUSE_DETECTION:
		//   false -> keep legacy behavior (no family-wide revoke on refresh token reuse).
		//   true  -> detect replay/reuse and revoke the whole rotation family.
		RefreshTokenReuseDetection: getenvBoolDefault("FEATURE_REFRESH_REUSE_DETECTION", false),
		SessionTokenEndpoint:       getenvBoolFirst([]string{"FEATURE_SESSION_TOKEN", "AUTH_FEATURE_SESSION_TOKEN"}, true),
		HostCookiePrefix:           getenvBoolFirst([]string{"FEATURE_HOST_COOKIE", "FEATURE_HOST_COOKIE_PREFIX", "SESSION_COOKIE_HOST_PREFIX"}, true),
		ClientProfiles:             getenvBoolDefault("FEATURE_CLIENT_PROFILES", true),
	}
}

// â”€â”€â”€ Inference Helpers â”€â”€â”€

func inferCookieSecure(baseURL, appEnv string) bool {
	if baseURL != "" {
		u, err := url.Parse(baseURL)
		if err == nil && u.Scheme != "" {
			if strings.EqualFold(u.Scheme, "https") {
				return true
			}
			if strings.EqualFold(u.Scheme, "http") {
				host := strings.ToLower(strings.TrimSpace(u.Hostname()))
				if host == "localhost" || host == "127.0.0.1" || host == "::1" {
					return false
				}
			}
		}
	}
	switch strings.ToLower(strings.TrimSpace(appEnv)) {
	case "dev", "development", "local", "test":
		return false
	default:
		return true
	}
}

func normalizeSessionCookieName(name string, secure bool, domain string, useHostPrefix bool) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = defaultSessionCookieRaw
	}

	domain = strings.TrimSpace(domain)
	hostPrefixAllowed := useHostPrefix && secure && domain == ""

	if strings.HasPrefix(name, "__Host-") && !hostPrefixAllowed {
		name = strings.TrimPrefix(name, "__Host-")
		if strings.TrimSpace(name) == "" {
			name = defaultSessionCookieRaw
		}
	}

	if hostPrefixAllowed && !strings.HasPrefix(name, "__Host-") {
		name = "__Host-" + strings.TrimPrefix(name, "__Secure-")
	}

	return name
}

func normalizeSameSite(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "strict":
		return "Strict"
	case "none":
		return "None"
	default:
		return "Lax"
	}
}

// â”€â”€â”€ Env Helpers â”€â”€â”€

func getenvStringDefault(key, def string) string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	return raw
}

func getenvStringFirst(keys []string, def string) string {
	for _, key := range keys {
		if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
			return raw
		}
	}
	return def
}

func getenvBoolDefault(key string, def bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return def
	}
	return v
}

func getenvBoolFirst(keys []string, def bool) bool {
	for _, key := range keys {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw == "" {
			continue
		}
		v, err := strconv.ParseBool(raw)
		if err == nil {
			return v
		}
	}
	return def
}

func getenvDurationDefault(key string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return def
	}
	return d
}

func getenvDurationFirst(keys []string, def time.Duration) time.Duration {
	for _, key := range keys {
		if raw := strings.TrimSpace(os.Getenv(key)); raw != "" {
			if d, err := time.ParseDuration(raw); err == nil {
				return d
			}
		}
	}
	return def
}

func getenvIntDefault(key string, def int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return v
}

func getenvBoolFirstOptional(keys []string) (bool, bool) {
	for _, key := range keys {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw == "" {
			continue
		}
		v, err := strconv.ParseBool(raw)
		if err == nil {
			return v, true
		}
	}
	return false, false
}

func getenvIntFirstOptional(keys []string) (int, bool) {
	for _, key := range keys {
		raw := strings.TrimSpace(os.Getenv(key))
		if raw == "" {
			continue
		}
		v, err := strconv.Atoi(raw)
		if err == nil {
			return v, true
		}
	}
	return 0, false
}

func loadEnvPasswordPolicyFromEnv() *repository.SecurityPolicy {
	policy := passwordpolicy.EffectiveSecurityPolicy(nil)
	configured := false

	if minLength, ok := getenvIntFirstOptional([]string{"SECURITY_PASSWORD_POLICY_MIN_LENGTH"}); ok {
		if minLength > 0 {
			policy.PasswordMinLength = minLength
		}
		configured = true
	}

	if requireUpper, ok := getenvBoolFirstOptional([]string{"SECURITY_PASSWORD_POLICY_REQUIRE_UPPER", "SECURITY_PASSWORD_POLICY_REQUIRE_UPPERCASE"}); ok {
		policy.RequireUppercase = requireUpper
		configured = true
	}
	if requireLower, ok := getenvBoolFirstOptional([]string{"SECURITY_PASSWORD_POLICY_REQUIRE_LOWER", "SECURITY_PASSWORD_POLICY_REQUIRE_LOWERCASE"}); ok {
		policy.RequireLowercase = requireLower
		configured = true
	}
	if requireNumbers, ok := getenvBoolFirstOptional([]string{"SECURITY_PASSWORD_POLICY_REQUIRE_DIGIT", "SECURITY_PASSWORD_POLICY_REQUIRE_NUMBER", "SECURITY_PASSWORD_POLICY_REQUIRE_NUMBERS"}); ok {
		policy.RequireNumbers = requireNumbers
		configured = true
	}
	if requireSymbols, ok := getenvBoolFirstOptional([]string{"SECURITY_PASSWORD_POLICY_REQUIRE_SYMBOL", "SECURITY_PASSWORD_POLICY_REQUIRE_SPECIAL", "SECURITY_PASSWORD_POLICY_REQUIRE_SPECIAL_CHAR", "SECURITY_PASSWORD_POLICY_REQUIRE_SPECIAL_CHARS"}); ok {
		policy.RequireSpecialChars = requireSymbols
		configured = true
	}
	if maxHistory, ok := getenvIntFirstOptional([]string{"SECURITY_PASSWORD_POLICY_MAX_HISTORY"}); ok {
		if maxHistory >= 0 {
			policy.MaxHistory = maxHistory
		}
		configured = true
	}
	if breachDetection, ok := getenvBoolFirstOptional([]string{"SECURITY_PASSWORD_POLICY_BREACH_DETECTION"}); ok {
		policy.BreachDetection = breachDetection
		configured = true
	}

	if !configured {
		return nil
	}
	return &policy
}

func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// â”€â”€â”€ Debug â”€â”€â”€

// String returns a safe debug representation of the config (no secrets).
func (c GlobalConfig) String() string {
	return fmt.Sprintf(
		"GlobalConfig{AppEnv=%s BaseURL=%s FSRoot=%s CORS=%v RefreshTTL=%s SessionTTL=%s Features=%+v}",
		c.AppEnv, c.BaseURL, c.FSRoot, c.CORSOrigins,
		c.RefreshTTL, c.SessionLoginConfig.TTL, c.Features,
	)
}
