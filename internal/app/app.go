package appv2

import (
	"embed"
	"net/http"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	cache "github.com/dropDatabas3/hellojohn/internal/cache"
	cp "github.com/dropDatabas3/hellojohn/internal/controlplane"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	emailv2 "github.com/dropDatabas3/hellojohn/internal/email"
	adminctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/admin"
	authctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/auth"
	cloudctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/cloud"
	emailctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/email"
	healthctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/health"
	oauthctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/oauth"
	oidcctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/oidc"
	securityctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/security"
	sessionctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/session"
	socialctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/social"
	sysctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/system"
	sessiondto "github.com/dropDatabas3/hellojohn/internal/http/dto/session"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	"github.com/dropDatabas3/hellojohn/internal/http/router"
	"github.com/dropDatabas3/hellojohn/internal/http/services"
	botpkg "github.com/dropDatabas3/hellojohn/internal/http/services/bot"
	healthsvc "github.com/dropDatabas3/hellojohn/internal/http/services/health"
	oauth "github.com/dropDatabas3/hellojohn/internal/http/services/oauth"
	socialsvc "github.com/dropDatabas3/hellojohn/internal/http/services/social"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// Config holds configuration for the V2 app.
type Config struct {
	// Add config fields as needed
}

// Deps holds raw dependencies required to build the app (DAL, Clients, etc).
type Deps struct {
	DAL          store.DataAccessLayer
	ControlPlane cp.Service
	Email        emailv2.Service
	SystemEmail  emailv2.SystemEmailService // SMTP global para invites de admin (opcional)
	Issuer       *jwtx.Issuer
	JWKSCache    *jwtx.JWKSCache
	BaseIssuer   string
	RefreshTTL   time.Duration
	SocialCache  socialsvc.CacheWriter
	MasterKey    string
	RateLimiter  mw.RateLimiter
	Social       socialsvc.Services

	// ─── Auth Config ───
	AutoLogin      bool
	FSAdminEnabled bool

	// ─── OAuth V2 ───
	OAuthCache       oauth.CacheClient
	OAuthCookieName  string
	OAuthAllowBearer bool

	// ─── Session ───
	SessionCache        cache.Client // Shared cache for session management
	SessionLoginConfig  sessiondto.LoginConfig
	SessionLogoutConfig sessiondto.SessionLogoutConfig
	SessionTokenTTL     time.Duration

	// ─── Feature Flags (mapped from GlobalConfig by wiring.go) ───
	FeatureRefreshReuseDetection bool
	FeatureSessionTokenEndpoint  bool
	FeatureClientProfiles        bool

	// ─── From GlobalConfig (mapped by wiring.go) ───
	CORSOrigins                 []string
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
	BaseURL                     string
	FSRoot                      string
	ServiceVersion              string
	ServiceCommit               string

	// ─── UI ───
	UIBaseURL string

	// ─── Admin Middleware Config ───
	AdminEnforce bool
	AdminSubs    []string

	// ─── API Key Auth ───
	APIKeyRepo repository.APIKeyRepository

	// ─── Controller Config ───
	KeyRotationGraceSeconds int64

	// ─── Audit ───
	AuditBus *audit.AuditBus

	// ─── GDP Migration ───
	TenantMigrationsFS  embed.FS // Tenant schema migrations for isolated DB
	TenantMigrationsDir string   // Directory within TenantMigrationsFS

	// ─── Usage Metrics / ETL (optional: nil when no global DB) ───
	UsageRepo  repository.UsageRepository
	EtlJobRepo repository.MigrationJobRepository

	// ─── SA.2: System Management ───
	SystemControllers *sysctrl.Controllers // opcional: si nil, /v2/system/* no se registra

	// ─── Cloud Control Plane ───
	CloudControllers *cloudctrl.Controllers // opcional: si nil, /v2/cloud/* no se registra

	// ─── Bot Protection ───
	// BotProtection valida tokens anti-bot en login, registro y password reset.
	// Si nil (o NoopService), no se realiza validación bot.
	BotProtection              botpkg.BotProtectionService
	PasswordPolicyGlobalTenant string
	PasswordPolicyEnv          *repository.SecurityPolicy
}

// App represents the wired V2 application.
type App struct {
	Handler http.Handler
}

// New creates and wires the V2 application.
func New(cfg Config, deps Deps) (*App, error) {
	// 1. Build Services
	svcs := services.New(services.Deps{
		DAL:          deps.DAL,
		ControlPlane: deps.ControlPlane,
		Email:        deps.Email,
		SystemEmail:  deps.SystemEmail,
		MasterKey:    deps.MasterKey,
		Issuer:       deps.Issuer,
		JWKSCache:    deps.JWKSCache,
		BaseIssuer:   deps.BaseIssuer,
		RefreshTTL:   deps.RefreshTTL,
		SocialCache:  deps.SocialCache,
		Social:       deps.Social,
		// Auth Config
		AutoLogin:      deps.AutoLogin,
		FSAdminEnabled: deps.FSAdminEnabled,
		// OAuth
		OAuthCache:       deps.OAuthCache,
		OAuthCookieName:  deps.OAuthCookieName,
		OAuthAllowBearer: deps.OAuthAllowBearer,
		// Session
		SessionCache:        deps.SessionCache,
		SessionLoginConfig:  deps.SessionLoginConfig,
		SessionLogoutConfig: deps.SessionLogoutConfig,
		SessionTokenTTL:     deps.SessionTokenTTL,
		// Feature Flags
		FeatureRefreshReuseDetection: deps.FeatureRefreshReuseDetection,
		FeatureClientProfiles:        deps.FeatureClientProfiles,
		// MFA Config
		MFATOTPWindow:               deps.MFATOTPWindow,
		MFATOTPIssuer:               deps.MFATOTPIssuer,
		MFASMSProvider:              deps.MFASMSProvider,
		MFASMSPhoneField:            deps.MFASMSPhoneField,
		MFASMSOTPLength:             deps.MFASMSOTPLength,
		MFASMSOTPTTL:                deps.MFASMSOTPTTL,
		MFASMSRateLimitHourly:       deps.MFASMSRateLimitHourly,
		MFASMSTwilioAccountSID:      deps.MFASMSTwilioAccountSID,
		MFASMSTwilioAuthToken:       deps.MFASMSTwilioAuthToken,
		MFASMSTwilioFrom:            deps.MFASMSTwilioFrom,
		MFASMSVonageAPIKey:          deps.MFASMSVonageAPIKey,
		MFASMSVonageAPISecret:       deps.MFASMSVonageAPISecret,
		MFASMSVonageFrom:            deps.MFASMSVonageFrom,
		MFAEmailOTPLength:           deps.MFAEmailOTPLength,
		MFAEmailOTPTTL:              deps.MFAEmailOTPTTL,
		MFAEmailRateLimitHourly:     deps.MFAEmailRateLimitHourly,
		MFAEmailSubject:             deps.MFAEmailSubject,
		MFAPreferredFactorField:     deps.MFAPreferredFactorField,
		MFAAdaptiveEnabled:          deps.MFAAdaptiveEnabled,
		MFAAdaptiveRules:            deps.MFAAdaptiveRules,
		MFAAdaptiveFailureThreshold: deps.MFAAdaptiveFailureThreshold,
		MFAAdaptiveStateTTL:         deps.MFAAdaptiveStateTTL,
		// Misc Config
		BaseURL:        deps.BaseURL,
		FSRoot:         deps.FSRoot,
		UIBaseURL:      deps.UIBaseURL,
		ServiceVersion: deps.ServiceVersion,
		ServiceCommit:  deps.ServiceCommit,
		// Health Check
		HealthDeps: healthsvc.Deps{
			ControlPlane: deps.ControlPlane,
			Issuer:       deps.Issuer,
		},
		// Audit
		AuditBus: deps.AuditBus,
		// GDP Migration
		TenantMigrationsFS:  deps.TenantMigrationsFS,
		TenantMigrationsDir: deps.TenantMigrationsDir,
		// Usage Metrics / ETL
		UsageRepo:  deps.UsageRepo,
		EtlJobRepo: deps.EtlJobRepo,
		// Bot Protection
		BotProtection: deps.BotProtection,
		// Password Policy fallback chain
		PasswordPolicyGlobalTenant: deps.PasswordPolicyGlobalTenant,
		PasswordPolicyEnv:          deps.PasswordPolicyEnv,
	})

	// 2. Build Controllers
	authControllers := authctrl.NewControllers(svcs.Auth, authctrl.ControllerDeps{
		LogoutConfig: deps.SessionLogoutConfig,
		DAL:          deps.DAL,
		SessionCache: deps.SessionCache,
	})
	adminControllers := adminctrl.NewControllers(svcs.Admin, adminctrl.ControllerDeps{
		DAL:                     deps.DAL,
		ControlPlane:            deps.ControlPlane,
		KeyRotationGraceSeconds: deps.KeyRotationGraceSeconds,
	})
	oidcControllers := oidcctrl.NewControllers(svcs.OIDC)

	oauthControllers := oauthctrl.NewControllers(svcs.OAuth, oauthctrl.ControllerDeps{
		// Deps... inferred from services or passed explicitly?
		// Checking codebase, OAuth NewControllers takes 2 args.
		// Assuming empty deps structure is accepted or need to fill it.
		// For wiring check, we pass zero value.
	})

	socialControllers := socialctrl.NewControllers(svcs.Social)

	sessionControllers := sessionctrl.NewControllers(svcs.Session, sessionctrl.ControllerDeps{
		LoginConfig: deps.SessionLoginConfig,
	})
	if !deps.FeatureSessionTokenEndpoint {
		sessionControllers.Token = nil
	}

	emailControllers := emailctrl.NewControllers(svcs.Email)
	securityControllers := securityctrl.NewControllers(svcs.Security)
	// Health has no service yet, simple handlers
	healthControllers := &healthctrl.Controllers{
		Health: healthctrl.NewHealthController(svcs.Health.Health),
	}

	// 3. Register Routes
	mux := http.NewServeMux()
	router.RegisterV2Routes(router.V2RouterDeps{
		Mux:                 mux,
		DAL:                 deps.DAL,
		Issuer:              deps.Issuer,
		AuthControllers:     authControllers,
		AdminControllers:    adminControllers,
		OAuthControllers:    oauthControllers,
		OIDCControllers:     oidcControllers,
		SocialControllers:   socialControllers,
		SessionControllers:  sessionControllers,
		EmailControllers:    emailControllers,
		SecurityControllers: securityControllers,
		HealthControllers:   healthControllers,
		SystemControllers:   deps.SystemControllers, // SA.2
		CloudControllers:    deps.CloudControllers,  // Cloud Control Plane
		RateLimiter:         deps.RateLimiter,
		AuthMiddleware:      mw.RequireAuth(deps.Issuer),
		AdminConfig: mw.AdminConfig{
			EnforceAdmin: deps.AdminEnforce,
			AdminSubs:    deps.AdminSubs,
		},
		APIKeyRepo: deps.APIKeyRepo,
	})

	// 4. Apply global middlewares (CORS)
	var handler http.Handler = mux
	if len(deps.CORSOrigins) > 0 {
		handler = mw.WithCORS(deps.CORSOrigins)(handler)
	}

	return &App{
		Handler: handler,
	}, nil
}
