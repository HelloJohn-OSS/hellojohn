// Package services agrupa todos los services HTTP V2.
// Este es el "composition root" de services.
//
//  1. CREAR EL SUB-PAQUETE:
//     internal/http/v2/services/{dominio}/
//     - {nombre}_service.go  → implementación del service
//     - services.go          → aggregator del dominio
//
// 2. DEFINIR EL AGGREGATOR DEL DOMINIO (services/{dominio}/services.go):
//
//	type Deps struct {
//	    // inyectar dependencias necesarias
//	}
//
//	type Services struct {
//	    MiService MiServiceInterface
//	}
//
//	func NewServices(d Deps) Services {
//	    return Services{
//	        MiService: NewMiService(d.AlgunaDep),
//	    }
//	}
//
// 3. AGREGAR AL AGGREGATOR PRINCIPAL (este archivo):
//   - Importar el paquete del dominio
//   - Agregar campo al struct Services
//   - Inicializar en el constructor New()
//
// 4. USO EN app.go o main.go:
//
//	deps := services.Deps{
//	    DAL:          dal,
//	    Issuer:       issuer,
//	    JWKSCache:    jwksCache,
//	    ControlPlane: cp,
//	    Email:        emailSvc,
//	    BaseIssuer:   cfg.BaseIssuer,
//	    RefreshTTL:   cfg.RefreshTTL,
//	    HealthDeps:   healthDeps,
//	}
//
//	svcs := services.New(deps)
//	// svcs.Admin.Clients, svcs.Auth.Login, svcs.OIDC.Discovery, etc.
//
// ═══════════════════════════════════════════════════════════════════════════════
package services

import (
	"embed"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	cache "github.com/dropDatabas3/hellojohn/internal/cache"
	controlplane "github.com/dropDatabas3/hellojohn/internal/controlplane"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	emailv2 "github.com/dropDatabas3/hellojohn/internal/email"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/session"
	"github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	"github.com/dropDatabas3/hellojohn/internal/http/services/auth"
	bot "github.com/dropDatabas3/hellojohn/internal/http/services/bot"
	cloudsvc "github.com/dropDatabas3/hellojohn/internal/http/services/cloud"
	"github.com/dropDatabas3/hellojohn/internal/http/services/email"
	"github.com/dropDatabas3/hellojohn/internal/http/services/health"
	"github.com/dropDatabas3/hellojohn/internal/http/services/oauth"
	"github.com/dropDatabas3/hellojohn/internal/http/services/oidc"
	"github.com/dropDatabas3/hellojohn/internal/http/services/security"
	"github.com/dropDatabas3/hellojohn/internal/http/services/session"
	"github.com/dropDatabas3/hellojohn/internal/http/services/social"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// Deps contiene las dependencias base para crear los services.
// Todas las dependencias externas se inyectan aquí.
type Deps struct {
	// ─── Infraestructura ───
	DAL          store.DataAccessLayer // Acceso a datos por tenant
	Issuer       *jwtx.Issuer          // Emisor JWT (keys, TTLs)
	JWKSCache    *jwtx.JWKSCache       // Cache de JWKS público
	ControlPlane controlplane.Service  // Operaciones FS (tenants, clients, scopes)
	Email        emailv2.Service       // Servicio de emails

	// ─── Configuración ───
	BaseIssuer string        // Issuer base (ej: "https://auth.example.com")
	RefreshTTL time.Duration // TTL para refresh tokens

	// ─── Health Check ───
	HealthDeps  health.Deps                // Dependencias específicas para health probes
	MasterKey   string                     // Master key hex para cifrado
	SystemEmail emailv2.SystemEmailService // SMTP global para emails del sistema (opcional)

	// ─── Social V2 ───
	SocialCache        social.CacheWriter // Cache con write capabilities para social
	SocialDebugPeek    bool               // Debug peek mode para result viewer
	SocialRegistry     *social.Registry   // Provider registry (replaces OIDCFactory)
	SocialStateSigner  social.StateSigner // Signer para state JWTs
	SocialLoginCodeTTL time.Duration      // TTL para login codes (default 60s)
	Social             social.Services    // Social services

	// ─── Auth Feature Flags ───
	AutoLogin      bool // Auto-login after registration
	FSAdminEnabled bool // Allow FS-admin registration

	// ─── OAuth V2 ───
	OAuthCache       oauth.CacheClient
	OAuthCookieName  string
	OAuthAllowBearer bool

	// ─── Session ───
	SessionCache        cache.Client // Shared cache for session management
	SessionLoginConfig  dto.LoginConfig
	SessionLogoutConfig dto.SessionLogoutConfig
	SessionTokenTTL     time.Duration

	// ─── Feature Flags (individual bools, no shared type) ───
	FeatureRefreshReuseDetection bool
	FeatureClientProfiles        bool

	// ─── MFA Config (from GlobalConfig) ───
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

	// ─── Misc Config (from GlobalConfig) ───
	BaseURL        string // Base URL for email links, etc.
	FSRoot         string // Control plane FS root
	UIBaseURL      string // Frontend base URL for OAuth consent
	ServiceVersion string
	ServiceCommit  string

	// ─── Audit ───
	AuditBus *audit.AuditBus

	// ─── GDP Migration ───
	TenantMigrationsFS  embed.FS // Tenant schema migrations (isolated DB)
	TenantMigrationsDir string   // Directory within TenantMigrationsFS

	// ─── Usage Metrics / ETL (optional: nil when no global DB) ───
	UsageRepo  repository.UsageRepository
	EtlJobRepo repository.MigrationJobRepository

	// ─── Bot Protection ───
	// BotProtection valida tokens anti-bot en login y registro.
	// Si nil, la validación se omite (sin-op).
	BotProtection              bot.BotProtectionService
	PasswordPolicyGlobalTenant string
	PasswordPolicyEnv          *repository.SecurityPolicy
}

// Services agrupa todos los sub-services por dominio.
// Cada dominio tiene su propio aggregator en su sub-paquete.
type Services struct {
	Admin    admin.Services   // Operaciones admin
	Auth     auth.Services    // Autenticación
	OIDC     oidc.Services    // OIDC
	OAuth    oauth.Services   // OAuth2 (authorize, token)
	Session  session.Services // Session management
	Email    email.Services   // Email flows
	Security security.Services
	Health   health.Services
	Social   social.Services
	Cloud    *cloudsvc.Services // Cloud Control Plane (nil si no configurado)
}

// New crea el agregador de services con todas las dependencias inyectadas.
// Este es el único lugar donde se instancian los services.
func New(d Deps) *Services {
	return &Services{
		Admin: admin.NewServices(admin.Deps{
			DAL:                         d.DAL,
			ControlPlane:                d.ControlPlane,
			Email:                       d.Email,
			SystemEmail:                 d.SystemEmail,
			MasterKey:                   d.MasterKey,
			Issuer:                      d.Issuer,
			RefreshTTL:                  d.RefreshTTL,
			BaseURL:                     d.BaseURL,
			UIBaseURL:                   d.UIBaseURL,
			SMSGlobalProvider:           d.MFASMSProvider,
			GlobalTOTPIssuer:            d.MFATOTPIssuer,
			GlobalTOTPWindow:            d.MFATOTPWindow,
			MFAAdaptiveEnabled:          d.MFAAdaptiveEnabled,
			MFAAdaptiveRules:            d.MFAAdaptiveRules,
			MFAAdaptiveFailureThreshold: d.MFAAdaptiveFailureThreshold,
			MFAAdaptiveStateTTL:         d.MFAAdaptiveStateTTL,
			AuditBus:                    d.AuditBus,
			TenantMigrationsFS:          d.TenantMigrationsFS,
			TenantMigrationsDir:         d.TenantMigrationsDir,
			UsageRepo:                   d.UsageRepo,
			EtlJobRepo:                  d.EtlJobRepo,
		}),
		Auth: auth.NewServices(auth.Deps{
			DAL:                         d.DAL,
			Issuer:                      d.Issuer,
			SessionCache:                d.SessionCache,
			RefreshTTL:                  d.RefreshTTL,
			ReuseDetection:              d.FeatureRefreshReuseDetection,
			ClaimsHook:                  nil, // NoOp por defecto, inyectar si se necesita
			AutoLogin:                   d.AutoLogin,
			FSAdminEnabled:              d.FSAdminEnabled,
			Email:                       d.Email,
			Social:                      d.Social,
			DataRoot:                    d.FSRoot,
			MFATOTPWindow:               d.MFATOTPWindow,
			MFATOTPIssuer:               d.MFATOTPIssuer,
			MFASMSProvider:              d.MFASMSProvider,
			MFASMSPhoneField:            d.MFASMSPhoneField,
			MFASMSOTPLength:             d.MFASMSOTPLength,
			MFASMSOTPTTL:                d.MFASMSOTPTTL,
			MFASMSRateLimitHourly:       d.MFASMSRateLimitHourly,
			MFASMSTwilioAccountSID:      d.MFASMSTwilioAccountSID,
			MFASMSTwilioAuthToken:       d.MFASMSTwilioAuthToken,
			MFASMSTwilioFrom:            d.MFASMSTwilioFrom,
			MFASMSVonageAPIKey:          d.MFASMSVonageAPIKey,
			MFASMSVonageAPISecret:       d.MFASMSVonageAPISecret,
			MFASMSVonageFrom:            d.MFASMSVonageFrom,
			MFAEmailOTPLength:           d.MFAEmailOTPLength,
			MFAEmailOTPTTL:              d.MFAEmailOTPTTL,
			MFAEmailRateLimitHourly:     d.MFAEmailRateLimitHourly,
			MFAEmailSubject:             d.MFAEmailSubject,
			MFAPreferredFactorField:     d.MFAPreferredFactorField,
			MFAAdaptiveEnabled:          d.MFAAdaptiveEnabled,
			MFAAdaptiveRules:            d.MFAAdaptiveRules,
			MFAAdaptiveFailureThreshold: d.MFAAdaptiveFailureThreshold,
			MFAAdaptiveStateTTL:         d.MFAAdaptiveStateTTL,
			AuditBus:                    d.AuditBus,
			BotProtection:               d.BotProtection,
			PasswordPolicyGlobalTenant:  d.PasswordPolicyGlobalTenant,
			PasswordPolicyEnv:           d.PasswordPolicyEnv,
		}),
		OIDC: oidc.NewServices(oidc.Deps{
			JWKSCache:    d.JWKSCache,
			BaseIssuer:   d.BaseIssuer,
			ControlPlane: d.ControlPlane,
			Issuer:       d.Issuer,
			DAL:          d.DAL,
		}),
		Health: health.NewServices(func() health.Deps {
			hd := d.HealthDeps
			hd.ServiceVersion = d.ServiceVersion
			hd.ServiceCommit = d.ServiceCommit
			return hd
		}()),
		Social: d.Social,
		OAuth: oauth.NewServices(oauth.Deps{
			DAL:                          d.DAL,
			Issuer:                       d.Issuer,
			RefreshTTL:                   d.RefreshTTL,
			Cache:                        d.OAuthCache,
			ControlPlane:                 d.ControlPlane,
			CookieName:                   d.OAuthCookieName,
			AllowBearer:                  d.OAuthAllowBearer,
			UIBaseURL:                    d.UIBaseURL,
			ClientProfilesEnabled:        d.FeatureClientProfiles,
			RefreshReuseDetectionEnabled: d.FeatureRefreshReuseDetection,
		}),
		Session: session.NewServices(session.Deps{
			Cache:       sessionCacheFromClient(d.SessionCache),
			LoginConfig: d.SessionLoginConfig,
			Issuer:      d.Issuer,
			TokenTTL:    d.SessionTokenTTL,
		}),
		Email: email.NewServices(email.Deps{
			Email:          d.Email,
			ControlPlane:   d.ControlPlane,
			VerifyTTL:      48 * time.Hour,
			ResetTTL:       1 * time.Hour,
			AutoLoginReset: d.AutoLogin,
			Issuer:         nil, // Implementar TokenIssuer adapter para soporte AutoLogin
		}),
		Security: security.NewServices(security.Deps{
			// Add security deps if any
		}),
	}
}

// sessionCacheFromClient wraps a cache.Client into a session.Cache adapter.
// Returns nil if the client is nil (graceful degradation).
func sessionCacheFromClient(c cache.Client) session.Cache {
	if c == nil {
		return nil
	}
	return session.NewCacheAdapter(c)
}
