package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	appv2 "github.com/dropDatabas3/hellojohn/internal/app"
	"github.com/dropDatabas3/hellojohn/internal/audit"
	cache "github.com/dropDatabas3/hellojohn/internal/cache"
	cloudpkg "github.com/dropDatabas3/hellojohn/internal/cloud"
	cp "github.com/dropDatabas3/hellojohn/internal/controlplane"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	emailv2 "github.com/dropDatabas3/hellojohn/internal/email"
	_ "github.com/dropDatabas3/hellojohn/internal/email/providers/mailgun"
	_ "github.com/dropDatabas3/hellojohn/internal/email/providers/resend"
	_ "github.com/dropDatabas3/hellojohn/internal/email/providers/sendgrid"
	cloudctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/cloud"
	sysctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/system"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	bot "github.com/dropDatabas3/hellojohn/internal/http/services/bot"
	cloudsvc "github.com/dropDatabas3/hellojohn/internal/http/services/cloud"
	oauth "github.com/dropDatabas3/hellojohn/internal/http/services/oauth"
	socialsvc "github.com/dropDatabas3/hellojohn/internal/http/services/social"
	syssvc "github.com/dropDatabas3/hellojohn/internal/http/services/system"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	metrics "github.com/dropDatabas3/hellojohn/internal/metrics"
	pwd "github.com/dropDatabas3/hellojohn/internal/security/password"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	pg "github.com/dropDatabas3/hellojohn/internal/store/adapters/pg"
	"github.com/dropDatabas3/hellojohn/internal/webhook"
	migrations "github.com/dropDatabas3/hellojohn/migrations/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BuildV2Handler builds the HTTP V2 handler with all dependencies wired.
// This function acts as the main entry point for the HTTP server to get the V2 handler.
// It instantiates dependencies (DAL, etc.) if they are not provided, or uses stubs for now.
func BuildV2Handler() (http.Handler, func() error, error) {
	handler, cleanup, _, err := buildV2HandlerInternal()
	return handler, cleanup, err
}

// BuildV2HandlerWithDeps builds the HTTP V2 handler and returns DAL for bootstrap
func BuildV2HandlerWithDeps() (http.Handler, func() error, store.DataAccessLayer, error) {
	return buildV2HandlerInternal()
}

// buildV2HandlerInternal is the internal implementation that returns all dependencies
func buildV2HandlerInternal() (http.Handler, func() error, store.DataAccessLayer, error) {
	ctx := context.Background()

	// 1. Config — single source of truth
	globalCfg := LoadGlobalConfig()

	// Critical keys — read from GlobalConfig (single source of truth per CLAUDE.md convention)
	masterKey := globalCfg.SigningMasterKey
	if len(masterKey) < 64 {
		return nil, nil, nil, fmt.Errorf("SIGNING_MASTER_KEY must be at least 64 hex characters (32 bytes)")
	}
	emailKey := globalCfg.SecretboxMasterKey

	// 2. Data Store (DAL + Manager)
	// Construir GlobalDB config si se provee GLOBAL_CONTROL_PLANE_DSN
	var globalDB *store.DBConfig
	if globalCfg.GlobalControlPlaneDSN != "" {
		// Normalize driver alias: "pg" and "" both map to the registered adapter name "postgres".
		driver := globalCfg.GlobalControlPlaneDriver
		if driver == "" || driver == "pg" {
			driver = "postgres"
		}
		globalDB = &store.DBConfig{
			Driver: driver,
			DSN:    globalCfg.GlobalControlPlaneDSN,
		}
	}

	// 2.1 Global Pool — pool de pgx directo para repos de usage + ETL (solo PG).
	// Separado del pool interno del manager para no interferir con sus migraciones.
	var globalPool *pgxpool.Pool
	var usageRepo repository.UsageRepository
	var migJobRepo repository.MigrationJobRepository
	if globalCfg.GlobalControlPlaneDSN != "" && (globalCfg.GlobalControlPlaneDriver == "" || globalCfg.GlobalControlPlaneDriver == "postgres" || globalCfg.GlobalControlPlaneDriver == "pg") {
		log.Printf("[wiring] GLOBAL_CONTROL_PLANE_DSN set — connecting to global pool...")
		if poolCfg, err := pgxpool.ParseConfig(globalCfg.GlobalControlPlaneDSN); err != nil {
			log.Printf("[wiring] ERROR: failed to parse GLOBAL_CONTROL_PLANE_DSN: %v — billing/onboard/tunnel routes will be UNAVAILABLE", err)
		} else if pool, err2 := pgxpool.NewWithConfig(ctx, poolCfg); err2 != nil {
			log.Printf("[wiring] ERROR: failed to connect global pool: %v — billing/onboard/tunnel routes will be UNAVAILABLE", err2)
		} else {
			globalPool = pool
			migJobRepo = pg.NewMigrationJobRepo(globalPool)
			log.Printf("[wiring] global pool connected OK — billing/onboard/tunnel routes ACTIVE")
		}
	}

	// SA.1: Determinar migraciones de Global DB según el driver
	// Solo PG tiene migraciones embebidas por ahora; MySQL se diferirá.
	var globalMigrFS embed.FS
	var globalMigrDir string
	if globalDB != nil {
		switch globalCfg.GlobalControlPlaneDriver {
		case "mysql":
			// TODO SA-MySQL: agregar migrations/mysql/embed.go cuando existan SQLs MySQL globales
			// Por ahora MySQL no tiene auto-migration de Global DB
		default: // "pg" o vacío → PostgreSQL (default)
			globalMigrFS = migrations.GlobalFS
			globalMigrDir = migrations.GlobalDir
		}
	}

	// GDP: Global Data Plane config
	var globalDataPlaneDB *store.DBConfig
	var gdpMigrFS embed.FS
	var gdpMigrDir string
	if globalCfg.GlobalDataPlaneDSN != "" {
		globalDataPlaneDB = &store.DBConfig{
			Driver:       "pg_shared",
			DSN:          globalCfg.GlobalDataPlaneDSN,
			MaxOpenConns: globalCfg.GlobalDataPlaneMaxOpenConns,
			MaxIdleConns: globalCfg.GlobalDataPlaneMaxIdleConns,
		}
		gdpMigrFS = migrations.GlobalDataPlaneFS
		gdpMigrDir = migrations.GlobalDataPlaneDir
	}

	manager, err := store.NewManager(ctx, store.ManagerConfig{
		FSRoot:           globalCfg.FSRoot,
		GlobalDB:         globalDB, // nil si no hay GLOBAL_CONTROL_PLANE_DSN → modo FS-only sin regresión
		SigningMasterKey: masterKey,
		Logger:           log.Default(),
		// Migraciones per-tenant embebidas
		MigrationsFS:  migrations.TenantFS,
		MigrationsDir: migrations.TenantDir,
		// SA.1: Migraciones de Global DB (solo PG por ahora)
		GlobalMigrationsFS:  globalMigrFS,
		GlobalMigrationsDir: globalMigrDir,
		// GDP: Global Data Plane (EPIC GDP)
		GlobalDataPlaneDB:            globalDataPlaneDB,
		GlobalDataPlaneMigrationsFS:  gdpMigrFS,
		GlobalDataPlaneMigrationsDir: gdpMigrDir,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to init store manager: %w", err)
	}

	// 2.2 Admin seed — si ADMIN_SEED_EMAIL y ADMIN_SEED_PASSWORD están seteados
	// y cp_admin está vacía, crea el primer admin automáticamente.
	// Es idempotente: no hace nada si ya hay admins. Seguro para producción.
	// El store.NewManager ya corrió las migraciones, así que cp_admin existe.
	if globalPool != nil && globalCfg.AdminSeedEmail != "" && globalCfg.AdminSeedPassword != "" {
		if seedErr := seedFirstAdmin(ctx, globalPool, globalCfg.AdminSeedEmail, globalCfg.AdminSeedPassword); seedErr != nil {
			log.Printf("[wiring] WARN: admin seed failed: %v", seedErr)
		}
	}

	// Cleanup for store
	cleanup := func() error {
		return manager.Close()
	}

	// 3. Keys & Issuer
	// Access keys via ConfigAccess (FS adapter)
	keyRepo := manager.ConfigAccess().Keys()

	// Keystore wrapper
	persistentKS := jwtx.NewPersistentKeystore(keyRepo)

	// Ensure minimal bootstrap (creates global keys if missing)
	if err := persistentKS.EnsureBootstrap(ctx); err != nil {
		_ = cleanup()
		return nil, nil, nil, fmt.Errorf("keystore bootstrap failed: %w", err)
	}

	issuer := jwtx.NewIssuer(globalCfg.BaseURL, persistentKS)

	// 3.5. JWKS Cache (15s TTL)
	// El loader recibe slug/ID del tenant y resuelve las keys
	jwksCache := jwtx.NewJWKSCache(15*time.Second, func(slugOrID string) (json.RawMessage, error) {
		// Global JWKS
		if strings.TrimSpace(slugOrID) == "" || strings.EqualFold(slugOrID, "global") {
			b, err := persistentKS.JWKSJSON()
			if err != nil {
				return nil, err
			}
			return json.RawMessage(b), nil
		}

		// Tenant JWKS - necesitamos resolver el tenant primero
		// porque JWKSJSONForTenant espera el slug exacto
		tda, err := manager.ForTenant(ctx, slugOrID)
		if err != nil {
			// Si el tenant no existe, retornar error
			return nil, fmt.Errorf("tenant not found: %w", err)
		}

		// Obtener JWKS usando el slug resuelto
		b, err := persistentKS.JWKSJSONForTenant(tda.Slug())
		if err != nil {
			return nil, err
		}
		return json.RawMessage(b), nil
	})

	// 4. Control Plane Service
	cpService := cp.NewService(manager)

	// 5. Email Service
	if _, err := validateSecretBoxKey(emailKey, "SECRETBOX_MASTER_KEY"); err != nil {
		_ = cleanup()
		return nil, nil, nil, err
	}

	systemEmailCfg := emailv2.SystemEmailConfig{
		Provider:       globalCfg.SystemEmail.Provider,
		FromEmail:      globalCfg.SystemEmail.FromEmail,
		ReplyTo:        globalCfg.SystemEmail.ReplyTo,
		TimeoutMs:      globalCfg.SystemEmail.TimeoutMs,
		ResendAPIKey:   globalCfg.SystemEmail.ResendAPIKey,
		SendGridAPIKey: globalCfg.SystemEmail.SendGridAPIKey,
		SendGridDomain: globalCfg.SystemEmail.SendGridDomain,
		MailgunAPIKey:  globalCfg.SystemEmail.MailgunAPIKey,
		MailgunDomain:  globalCfg.SystemEmail.MailgunDomain,
		MailgunRegion:  globalCfg.SystemEmail.MailgunRegion,
		SMTP: emailv2.SystemSMTPConfig{
			Host:     globalCfg.SystemEmail.SMTP.Host,
			Port:     globalCfg.SystemEmail.SMTP.Port,
			User:     globalCfg.SystemEmail.SMTP.User,
			Password: globalCfg.SystemEmail.SMTP.Password,
			From:     globalCfg.SystemEmail.SMTP.From,
		},
	}

	emailService, err := emailv2.NewService(emailv2.ServiceConfig{
		DAL:            manager,
		MasterKey:      emailKey,
		BaseURL:        globalCfg.BaseURL,
		VerifyTTL:      48 * time.Hour,
		ResetTTL:       1 * time.Hour,
		SystemEmail:    systemEmailCfg,
		SystemSettings: manager.ConfigAccess().SystemSettings(),
	})
	if err != nil {
		_ = cleanup()
		return nil, nil, nil, fmt.Errorf("email v2 init failed: %w", err)
	}

	// System Email Service (usa Global Provider del control plane + fallback env)
	systemEmailService := emailv2.NewSystemEmailServiceWithSources(systemEmailCfg, emailKey, manager.ConfigAccess().SystemSettings())

	// 5.5 Bot Protection Service
	var botSvc bot.BotProtectionService
	if globalCfg.BotProtectionEnabled && globalCfg.TurnstileSecretKey != "" {
		botSvc = bot.New(bot.Deps{
			DAL:                manager,
			GlobalEnabled:      globalCfg.BotProtectionEnabled,
			GlobalProvider:     globalCfg.BotProtectionProvider,
			GlobalSecretKey:    globalCfg.TurnstileSecretKey,
			GlobalSiteKey:      globalCfg.TurnstileSiteKey,
			GlobalProtectLogin: globalCfg.BotProtectLogin,
			GlobalProtectReg:   globalCfg.BotProtectRegistration,
			GlobalProtectReset: globalCfg.BotProtectPasswordReset,
		})
		log.Printf(`{"level":"info","msg":"bot_protection_enabled","provider":"%s"}`, globalCfg.BotProtectionProvider)
	} else {
		botSvc = bot.NewNoop()
	}

	// 6. Shared Cache (single instance for OAuth, Social, Session)
	// All three subsystems use the same underlying cache so that OAuth authorize
	// can find sessions created by session login (key format: "sid:{hash}").
	sharedCache := cache.NewMemory("hj")
	socialCacheAdapter := socialsvc.NewCacheAdapter(sharedCache)
	oauthCacheAdapter := oauth.NewCacheAdapter(sharedCache)

	// 6.5 Audit Bus — async event pipeline with DB writer
	dbWriter := audit.NewDBWriter(func(ctx context.Context, tenantID string) (audit.TenantAuditRepo, error) {
		tda, err := manager.ForTenant(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		if err := tda.RequireDB(); err != nil {
			return nil, err
		}
		return tda.Audit(), nil
	}, log.Default())

	controlPlaneWriter := audit.NewControlPlaneWriter(globalCfg.AuditControlPlaneLogPath, log.Default())
	overflowWriter := audit.NewFileWriter(globalCfg.AuditOverflowLogPath, log.Default())
	dbWriter.SetDeadLetterWriter(overflowWriter)

	webhookResolver := &webhookResolverImpl{DAL: manager}
	webhookWriter := &webhook.Writer{Resolver: webhookResolver} // [Fase 5.2] Event Router Plugin

	writers := []audit.Writer{dbWriter, controlPlaneWriter, webhookWriter}
	if globalCfg.AuditStdoutEnabled {
		writers = append(writers, &audit.StdoutWriter{})
	}
	// UsageCollector: agrega métricas de uso a los eventos de audit (solo si hay global DB PG)
	var usageCollector *metrics.UsageCollector
	if usageRepo != nil {
		usageCollector = metrics.NewUsageCollector(usageRepo)
		writers = append(writers, usageCollector)
	}
	auditBus := audit.NewAuditBus(writers...)
	auditBus.SetOverflowWriter(overflowWriter)
	auditBus.Start()
	if usageCollector != nil {
		usageCollector.Start()
	}

	// 6.6 Audit Purge Cron — periodic cleanup of old audit events
	purgeLister, purgePurger := audit.NewPurgeAdapter(audit.PurgeDeps{
		ListTenantsFn: func(ctx context.Context) ([]audit.TenantInfo, error) {
			tenants, err := cpService.ListTenants(ctx)
			if err != nil {
				return nil, err
			}
			out := make([]audit.TenantInfo, 0, len(tenants))
			for _, t := range tenants {
				days := t.Settings.AuditRetentionDays
				out = append(out, audit.TenantInfo{
					Slug:          t.Slug,
					RetentionDays: days,
				})
			}
			return out, nil
		},
		PurgeFn: func(ctx context.Context, tenantSlug string, before time.Time) (int64, error) {
			tda, err := manager.ForTenant(ctx, tenantSlug)
			if err != nil {
				return 0, err
			}
			if err := tda.RequireDB(); err != nil {
				return 0, nil // skip tenants without DB
			}
			return tda.Audit().Purge(ctx, before)
		},
	})
	purgeCron := audit.NewPurgeCron(purgeLister, purgePurger, 24*time.Hour, log.Default())
	purgeCron.Start()

	origCleanup := cleanup
	cleanup = func() error {
		purgeCron.Stop()
		if usageCollector != nil {
			usageCollector.Stop()
		}
		auditBus.Stop()
		if globalPool != nil {
			globalPool.Close()
		}
		return origCleanup()
	}

	// 7. Rate Limiter — in-memory fixed-window, enabled by default.
	// Replace with a Redis-backed limiter in multi-node deployments.
	var rateLimiter mw.RateLimiter
	if globalCfg.RateLimitEnabled {
		memRL := mw.NewMemoryRateLimiter(int64(globalCfg.RateLimitMax), globalCfg.RateLimitWindow)
		rateLimiter = memRL
		prevCleanup := cleanup
		cleanup = func() error {
			memRL.Stop()
			return prevCleanup()
		}
		log.Printf(`{"level":"info","msg":"rate_limiter_enabled","max":%d,"window":"%s"}`,
			globalCfg.RateLimitMax, globalCfg.RateLimitWindow)
	}

	// Dedicated limiter for tenant test mailing endpoint:
	// max 5 requests/minute per tenant.
	mailingTestLimiter := mw.NewMemoryRateLimiter(5, time.Minute)
	prevCleanup := cleanup
	cleanup = func() error {
		mailingTestLimiter.Stop()
		return prevCleanup()
	}
	log.Printf(`{"level":"info","msg":"tenant_mailing_test_rate_limiter_enabled","max":5,"window":"1m"}`)

	// 8. Dependencies Struct
	deps := appv2.Deps{
		DAL:                    manager,
		ControlPlane:           cpService,
		Email:                  emailService,
		SystemEmail:            systemEmailService,
		SystemEmailEnv:         systemEmailCfg,
		Issuer:                 issuer,
		JWKSCache:              jwksCache,
		BaseIssuer:             globalCfg.BaseURL,
		RefreshTTL:             globalCfg.RefreshTTL,
		SocialCache:            socialCacheAdapter,
		MasterKey:              masterKey,
		RateLimiter:            rateLimiter,
		MailingTestRateLimiter: mailingTestLimiter,
		// Auth Config
		AutoLogin:      globalCfg.AutoLogin,
		FSAdminEnabled: globalCfg.FSAdminEnabled,
		Social: socialsvc.NewServices(socialsvc.Deps{
			DAL:            manager,
			Cache:          socialCacheAdapter,
			Issuer:         issuer,
			BaseURL:        globalCfg.BaseURL,
			RefreshTTL:     globalCfg.RefreshTTL,
			LoginCodeTTL:   globalCfg.SocialLoginCodeTTL,
			TenantProvider: cpService,
			AuditBus:       auditBus,
			Registry: func() *socialsvc.Registry {
				r := socialsvc.NewRegistry()
				r.Register("google", &socialsvc.GoogleFactory{TenantProvider: cpService})
				r.Register("github", &socialsvc.GitHubFactory{TenantProvider: cpService})
				r.Register("facebook", &socialsvc.FacebookFactory{TenantProvider: cpService})
				r.Register("discord", &socialsvc.DiscordFactory{TenantProvider: cpService})
				r.Register("microsoft", &socialsvc.MicrosoftFactory{TenantProvider: cpService})
				r.Register("linkedin", &socialsvc.LinkedInFactory{TenantProvider: cpService})
				r.Register("gitlab", &socialsvc.GitLabFactory{TenantProvider: cpService})
				r.Register("apple", &socialsvc.AppleFactory{TenantProvider: cpService})
				return r
			}(),
			StateSigner: socialsvc.NewIssuerAdapter(issuer, 15*time.Minute),
		}),
		// OAuth
		OAuthCache:       oauthCacheAdapter,
		OAuthCookieName:  globalCfg.OAuthCookieName,
		OAuthAllowBearer: globalCfg.OAuthAllowBearer,
		// Session
		SessionCache:        sharedCache,
		SessionLoginConfig:  globalCfg.SessionLoginConfig,
		SessionLogoutConfig: globalCfg.SessionLogoutConfig,
		SessionTokenTTL:     globalCfg.SessionTokenTTL,
		// Feature Flags
		FeatureRefreshReuseDetection: globalCfg.Features.RefreshTokenReuseDetection,
		FeatureSessionTokenEndpoint:  globalCfg.Features.SessionTokenEndpoint,
		FeatureClientProfiles:        globalCfg.Features.ClientProfiles,
		// CORS
		CORSOrigins: globalCfg.CORSOrigins,
		// MFA Config
		MFATOTPWindow:               globalCfg.MFATOTPWindow,
		MFATOTPIssuer:               globalCfg.MFATOTPIssuer,
		MFASMSProvider:              globalCfg.MFASMSProvider,
		MFASMSPhoneField:            globalCfg.MFASMSPhoneField,
		MFASMSOTPLength:             globalCfg.MFASMSOTPLength,
		MFASMSOTPTTL:                globalCfg.MFASMSOTPTTL,
		MFASMSRateLimitHourly:       globalCfg.MFASMSRateLimitHourly,
		MFASMSTwilioAccountSID:      globalCfg.MFASMSTwilioAccountSID,
		MFASMSTwilioAuthToken:       globalCfg.MFASMSTwilioAuthToken,
		MFASMSTwilioFrom:            globalCfg.MFASMSTwilioFrom,
		MFASMSVonageAPIKey:          globalCfg.MFASMSVonageAPIKey,
		MFASMSVonageAPISecret:       globalCfg.MFASMSVonageAPISecret,
		MFASMSVonageFrom:            globalCfg.MFASMSVonageFrom,
		MFAEmailOTPLength:           globalCfg.MFAEmailOTPLength,
		MFAEmailOTPTTL:              globalCfg.MFAEmailOTPTTL,
		MFAEmailRateLimitHourly:     globalCfg.MFAEmailRateLimitHourly,
		MFAEmailSubject:             globalCfg.MFAEmailSubject,
		MFAPreferredFactorField:     globalCfg.MFAPreferredFactorField,
		MFAAdaptiveEnabled:          globalCfg.MFAAdaptiveEnabled,
		MFAAdaptiveRules:            globalCfg.MFAAdaptiveRules,
		MFAAdaptiveFailureThreshold: globalCfg.MFAAdaptiveFailureThreshold,
		MFAAdaptiveStateTTL:         globalCfg.MFAAdaptiveStateTTL,
		// Misc Config (threaded to services)
		BaseURL:        globalCfg.BaseURL,
		FSRoot:         globalCfg.FSRoot,
		ServiceVersion: globalCfg.ServiceVersion,
		ServiceCommit:  globalCfg.ServiceCommit,
		// UI
		UIBaseURL: globalCfg.UIBaseURL,
		// Admin Middleware Config
		AdminEnforce: globalCfg.AdminEnforce,
		AdminSubs:    globalCfg.AdminSubs,
		// API Key Auth
		APIKeyRepo: manager.ConfigAccess().APIKeys(),
		// Controller Config
		KeyRotationGraceSeconds: globalCfg.KeyRotationGrace,
		// Audit
		AuditBus: auditBus,
		// GDP Migration — tenant migrations for isolated DB target
		TenantMigrationsFS:  migrations.TenantFS,
		TenantMigrationsDir: migrations.TenantDir,
		// Usage Metrics / ETL (nil when no global DB or non-PG driver)
		UsageRepo:  usageRepo,
		EtlJobRepo: migJobRepo,
		// Bot Protection
		BotProtection: botSvc,
		// Password Policy fallback chain
		PasswordPolicyGlobalTenant: globalCfg.PasswordPolicyGlobalTenant,
		PasswordPolicyEnv:          globalCfg.PasswordPolicyEnv,
	}

	// SA.2: System Management — instanciar service + controllers
	// GlobalDSN y GlobalDriver se pasan desde globalCfg (no os.Getenv)
	metricsCollector := metrics.NewCollector()
	systemService := syssvc.New(syssvc.SystemDeps{
		DAL:          manager,
		FSRoot:       globalCfg.FSRoot,
		GlobalDSN:    globalCfg.GlobalControlPlaneDSN,
		GlobalDriver: globalCfg.GlobalControlPlaneDriver,
		Logger:       log.Default(),
		StartTime:    time.Now(),
		Version:      "", // vacío en dev; setear con APP_VERSION si se desea
		Metrics:      metricsCollector,
	})
	deps.SystemControllers = sysctrl.NewControllers(systemService, metricsCollector)

	// Cloud Control Plane (optional: only when global DB is configured)
	cloudSvcs := cloudsvc.New(cloudsvc.Deps{
		ConfigAccess:          manager.ConfigAccess(),
		Issuer:                issuer,
		CloudOIDCIssuer:       globalCfg.CloudOIDCIssuer,
		CloudOIDCClientID:     globalCfg.CloudOIDCClientID,
		CloudOIDCClientSecret: globalCfg.CloudOIDCClientSecret,
		CloudOIDCRedirectURI:  globalCfg.CloudOIDCRedirectURI,
		AllowInsecure:         globalCfg.CloudAllowInsecure,
		BaseURL:               globalCfg.BaseURL,
		ProxyRateLimitRead:    globalCfg.CloudProxyRateLimitRead,
		ProxyRateLimitWrite:   globalCfg.CloudProxyRateLimitWrite,
		AuditBus:              auditBus,
	})
	if cloudSvcs != nil && cloudSvcs.CloudInstances != nil {
		checker := cloudpkg.NewHealthChecker(cloudSvcs.CloudInstances)
		go checker.Start(ctx)
	}
	deps.CloudControllers = cloudctrl.NewControllers(cloudSvcs, cloudctrl.ControllerDeps{
		BaseURL: globalCfg.BaseURL,
	})

	// 8. Build App (Router, Controllers)
	app, err := appv2.New(appv2.Config{}, deps)
	if err != nil {
		_ = cleanup()
		return nil, nil, nil, fmt.Errorf("failed to build v2 app: %w", err)
	}

	// Inyectar / Lanzar el Supervisor de Webhooks Background (Fase 5.3)
	// Operará bajo un Heartbeat pasivo recolectando deliveries atrasados del DAL
	go webhook.StartWorker(ctx, cpService, manager)

	// Cloud extensions (no-op en OSS, implementado en wiring_cloud.go para cloud)
	cloudMux := http.NewServeMux()
	var proxyForCloud cloudsvc.ProxyService
	if cloudSvcs != nil {
		proxyForCloud = cloudSvcs.Proxy
	}
	registerCloudExtensions(cloudMux, cloudDeps{
		adminRepo:        manager.ConfigAccess().Admins(),
		refreshTokenRepo: manager.ConfigAccess().AdminRefreshTokens(),
		systemEmail:      systemEmailService,
		issuer:           issuer,
		globalCfg:        globalCfg,
		globalPool:       globalPool,
		controlPlane:     cpService,
		dal:              manager,
		proxy:            proxyForCloud,
	})

	cloudHandler := http.Handler(cloudMux)
	cloudHandler = mw.WithRecover()(cloudHandler)
	cloudHandler = mw.WithRequestID()(cloudHandler)
	cloudHandler = mw.WithLogging()(cloudHandler)
	if len(globalCfg.CORSOrigins) > 0 {
		cloudHandler = mw.WithCORS(globalCfg.CORSOrigins)(cloudHandler)
	}

	handler := metrics.NewMiddleware(metricsCollector)(layerCloudRoutes(cloudMux, cloudHandler, app.Handler))
	return handler, cleanup, manager, nil
}

func validateSecretBoxKey(val, name string) (string, error) {
	val = strings.TrimSpace(val)
	if val == "" {
		return "", fmt.Errorf("%s required", name)
	}
	// Try Base64 (Std)
	if b, err := base64.StdEncoding.DecodeString(val); err == nil && len(b) == 32 {
		return val, nil
	}
	// Try Base64 (Raw)
	if b, err := base64.RawStdEncoding.DecodeString(val); err == nil && len(b) == 32 {
		return val, nil
	}
	// Try Hex
	if len(val) == 64 {
		if b, err := hex.DecodeString(val); err == nil && len(b) == 32 {
			return val, nil
		}
	}
	// Try Raw
	if len(val) == 32 {
		return val, nil
	}
	return "", fmt.Errorf("%s must be 32 bytes (base64 std/raw, hex 64 chars, or raw 32 chars)", name)
}

// webhookResolverImpl acts as an adapter resolving webhook configurations from the Store.
type webhookResolverImpl struct {
	DAL store.DataAccessLayer
}

func (r *webhookResolverImpl) Resolve(ctx context.Context, tenantID string) ([]repository.WebhookConfig, webhook.WebhookInserter, error) {
	tda, err := r.DAL.ForTenant(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	if err := tda.RequireDB(); err != nil {
		return nil, nil, nil // Graeful skip if tenant lacks Database support yet.
	}
	settings := tda.Settings()
	if settings == nil || len(settings.Webhooks) == 0 {
		return nil, nil, nil
	}
	return settings.Webhooks, tda.Webhooks(), nil
}

// ─── Stubs for Compilation (mocks) ───

// cloudDeps agrupa las dependencias que wiring.go pasa a las extensiones cloud.
// En el build OSS las extensiones son no-ops; en el build cloud (wiring_cloud.go)
// se usan para registrar rutas adicionales.
type cloudDeps struct {
	adminRepo        repository.AdminRepository
	refreshTokenRepo repository.AdminRefreshTokenRepository
	systemEmail      emailv2.SystemEmailService
	issuer           *jwtx.Issuer
	globalCfg        GlobalConfig
	globalPool       *pgxpool.Pool
	controlPlane     cp.Service
	dal              store.DataAccessLayer
	proxy            cloudsvc.ProxyService // EPIC_014: relay hub injection point
}

// layerCloudRoutes combina el mux de rutas cloud con el handler principal.
// En el build OSS cloudMux no tiene rutas registradas, por lo que todas las
// peticiones caen al handler principal. En el build cloud, las rutas registradas
// en cloudMux tienen prioridad.
func layerCloudRoutes(cloud *http.ServeMux, cloudHandler http.Handler, primary http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := cloud.Handler(r)
		if pattern != "" {
			cloudHandler.ServeHTTP(w, r)
			return
		}
		primary.ServeHTTP(w, r)
	})
}

type NoOpEmailService struct{}

func (s *NoOpEmailService) GetSender(ctx context.Context, tenantSlugOrID string) (emailv2.Sender, error) {
	return nil, nil
}
func (s *NoOpEmailService) SendVerificationEmail(ctx context.Context, req emailv2.SendVerificationRequest) error {
	return nil
}
func (s *NoOpEmailService) SendPasswordResetEmail(ctx context.Context, req emailv2.SendPasswordResetRequest) error {
	return nil
}
func (s *NoOpEmailService) SendNotificationEmail(ctx context.Context, req emailv2.SendNotificationRequest) error {
	return nil
}
func (s *NoOpEmailService) TestSMTP(ctx context.Context, tenantSlugOrID, recipientEmail string, override *emailv2.SMTPConfig) error {
	return nil
}

// MockKeyRepository implements repository.KeyRepository
type MockKeyRepository struct{}

func (m *MockKeyRepository) GetActive(ctx context.Context, tenantID string) (*repository.SigningKey, error) {
	// Return a static key for testing
	pub, priv, _ := ed25519.GenerateKey(nil)
	return &repository.SigningKey{
		ID:         "mock-kid",
		Algorithm:  "EdDSA",
		PrivateKey: priv,
		PublicKey:  pub,
		Status:     repository.KeyStatusActive,
		CreatedAt:  time.Now(),
	}, nil
}
func (m *MockKeyRepository) GetByKID(ctx context.Context, kid string) (*repository.SigningKey, error) {
	return m.GetActive(ctx, "")
}
func (m *MockKeyRepository) GetJWKS(ctx context.Context, tenantID string) (*repository.JWKS, error) {
	return &repository.JWKS{Keys: []repository.JWK{}}, nil
}
func (m *MockKeyRepository) Generate(ctx context.Context, tenantID, algorithm string) (*repository.SigningKey, error) {
	return m.GetActive(ctx, "")
}
func (m *MockKeyRepository) Rotate(ctx context.Context, tenantID string, gracePeriod time.Duration) (*repository.SigningKey, error) {
	return m.GetActive(ctx, "")
}
func (m *MockKeyRepository) Revoke(ctx context.Context, kid string) error { return nil }

func (m *MockKeyRepository) ToEdDSA(key *repository.SigningKey) (ed25519.PrivateKey, error) {
	if k, ok := key.PrivateKey.(ed25519.PrivateKey); ok {
		return k, nil
	}
	return nil, fmt.Errorf("invalid key type")
}
func (m *MockKeyRepository) ToECDSA(key *repository.SigningKey) (*ecdsa.PrivateKey, error) {
	return nil, fmt.Errorf("not implemented")
}

// MockControlPlane implements cp.Service
type MockControlPlane struct{}

func (m *MockControlPlane) ListTenants(ctx context.Context) ([]repository.Tenant, error) {
	return nil, nil
}
func (m *MockControlPlane) GetTenant(ctx context.Context, slug string) (*repository.Tenant, error) {
	return nil, nil
}
func (m *MockControlPlane) GetTenantByID(ctx context.Context, id string) (*repository.Tenant, error) {
	return nil, nil
}
func (m *MockControlPlane) CreateTenant(ctx context.Context, name, slug, language string) (*repository.Tenant, error) {
	return nil, nil
}
func (m *MockControlPlane) UpdateTenant(ctx context.Context, tenant *repository.Tenant) error {
	return nil
}
func (m *MockControlPlane) DeleteTenant(ctx context.Context, slug string) error { return nil }
func (m *MockControlPlane) UpdateTenantSettings(ctx context.Context, slug string, settings *repository.TenantSettings) error {
	return nil
}
func (m *MockControlPlane) ListClients(ctx context.Context, slug string) ([]repository.Client, error) {
	return nil, nil
}
func (m *MockControlPlane) GetClient(ctx context.Context, slug, clientID string) (*repository.Client, error) {
	return nil, nil
}
func (m *MockControlPlane) CreateClient(ctx context.Context, slug string, input cp.ClientInput) (*repository.Client, error) {
	return nil, nil
}
func (m *MockControlPlane) UpdateClient(ctx context.Context, slug string, input cp.ClientInput) (*repository.Client, error) {
	return nil, nil
}
func (m *MockControlPlane) DeleteClient(ctx context.Context, slug, clientID string) error { return nil }
func (m *MockControlPlane) DecryptClientSecret(ctx context.Context, slug, clientID string) (string, error) {
	return "", nil
}
func (m *MockControlPlane) ListScopes(ctx context.Context, slug string) ([]repository.Scope, error) {
	return nil, nil
}
func (m *MockControlPlane) CreateScope(ctx context.Context, slug string, input repository.ScopeInput) (*repository.Scope, error) {
	return nil, nil
}
func (m *MockControlPlane) DeleteScope(ctx context.Context, slug, name string) error { return nil }
func (m *MockControlPlane) ValidateClientID(id string) bool                          { return true }
func (m *MockControlPlane) ValidateRedirectURI(uri string) bool                      { return true }
func (m *MockControlPlane) IsScopeAllowed(client *repository.Client, scope string) bool {
	return true
}

// ─── Additional Stubs for Login Service ───

// ─── Additional Stubs for Login Service ───

// MockDAL implements store.DataAccessLayer
type MockDAL struct{}

func (m *MockDAL) ForTenant(ctx context.Context, slugOrID string) (store.TenantDataAccess, error) {
	return &MockTDA{slug: slugOrID}, nil
}
func (m *MockDAL) ConfigAccess() store.ConfigAccess { return nil }
func (m *MockDAL) Mode() store.OperationalMode      { return store.ModeFSTenantDB }
func (m *MockDAL) Capabilities() store.ModeCapabilities {
	return store.GetCapabilities(store.ModeFSTenantDB)
}
func (m *MockDAL) Stats() store.FactoryStats { return store.FactoryStats{} }
func (m *MockDAL) MigrateTenant(ctx context.Context, slugOrID string) (*store.MigrationResult, error) {
	return nil, nil
}
func (m *MockDAL) Close() error { return nil }

// MockTDA implements store.TenantDataAccess
type MockTDA struct {
	slug string
}

func (m *MockTDA) Slug() string { return m.slug }
func (m *MockTDA) ID() string   { return m.slug }
func (m *MockTDA) Settings() *repository.TenantSettings {
	return &repository.TenantSettings{IssuerMode: "path"}
}
func (m *MockTDA) Driver() string { return "mock" }

func (m *MockTDA) Users() repository.UserRepository                                { return &MockUserRepo{} }
func (m *MockTDA) Tokens() repository.TokenRepository                              { return &MockTokenRepo{} }
func (m *MockTDA) Clients() repository.ClientRepository                            { return &MockClientRepo{} }
func (m *MockTDA) MFA() repository.MFARepository                                   { return &MockMFARepo{} }
func (m *MockTDA) Consents() repository.ConsentRepository                          { return nil }
func (m *MockTDA) RBAC() repository.RBACRepository                                 { return nil }
func (m *MockTDA) Schema() repository.SchemaRepository                             { return nil }
func (m *MockTDA) EmailTokens() repository.EmailTokenRepository                    { return nil }
func (m *MockTDA) Identities() repository.IdentityRepository                       { return nil }
func (m *MockTDA) Scopes() repository.ScopeRepository                              { return nil }
func (m *MockTDA) Sessions() repository.SessionRepository                          { return nil }
func (m *MockTDA) Audit() repository.AuditRepository                               { return nil }
func (m *MockTDA) Claims() repository.ClaimRepository                              { return nil }
func (m *MockTDA) Webhooks() repository.WebhookRepository                          { return nil }
func (m *MockTDA) Invitations() repository.InvitationRepository                    { return nil }
func (m *MockTDA) WebAuthn() repository.WebAuthnRepository                         { return nil }
func (m *MockTDA) Cache() cache.Client                                             { return nil }
func (m *MockTDA) CacheRepo() repository.CacheRepository                           { return nil }
func (m *MockTDA) Mailer() store.MailSender                                        { return nil }
func (m *MockTDA) InfraStats(ctx context.Context) (*store.TenantInfraStats, error) { return nil, nil }
func (m *MockTDA) HasDB() bool                                                     { return true }
func (m *MockTDA) RequireDB() error                                                { return nil }

// MockUserRepo
type MockUserRepo struct{}

func (m *MockUserRepo) GetByEmail(ctx context.Context, tenantID, email string) (*repository.User, *repository.Identity, error) {
	return nil, nil, repository.ErrNotFound
}
func (m *MockUserRepo) GetByID(ctx context.Context, userID string) (*repository.User, error) {
	return nil, repository.ErrNotFound
}
func (m *MockUserRepo) CheckPassword(hash *string, password string) bool { return false }
func (m *MockUserRepo) Create(ctx context.Context, input repository.CreateUserInput) (*repository.User, *repository.Identity, error) {
	return nil, nil, repository.ErrNotImplemented
}
func (m *MockUserRepo) CreateBatch(ctx context.Context, tenantID string, users []repository.CreateUserInput) (created, failed int, err error) {
	return 0, 0, repository.ErrNotImplemented
}
func (m *MockUserRepo) Update(ctx context.Context, userID string, input repository.UpdateUserInput) error {
	return repository.ErrNotImplemented
}
func (m *MockUserRepo) Disable(ctx context.Context, userID, by, reason string, until *time.Time) error {
	return repository.ErrNotImplemented
}
func (m *MockUserRepo) Enable(ctx context.Context, userID, by string) error {
	return repository.ErrNotImplemented
}
func (m *MockUserRepo) SetEmailVerified(ctx context.Context, userID string, verified bool) error {
	return repository.ErrNotImplemented
}
func (m *MockUserRepo) UpdatePasswordHash(ctx context.Context, userID, newHash string) error {
	return repository.ErrNotImplemented
}
func (m *MockUserRepo) ListPasswordHistory(ctx context.Context, userID string, limit int) ([]string, error) {
	return nil, repository.ErrNotImplemented
}
func (m *MockUserRepo) RotatePasswordHash(ctx context.Context, userID, newHash string, keepHistory int) error {
	return repository.ErrNotImplemented
}
func (m *MockUserRepo) List(ctx context.Context, tenantID string, filter repository.ListUsersFilter) ([]repository.User, error) {
	return nil, repository.ErrNotImplemented
}
func (m *MockUserRepo) Delete(ctx context.Context, userID string) error {
	return repository.ErrNotImplemented
}

// MockTokenRepo
type MockTokenRepo struct{}

func (m *MockTokenRepo) Create(ctx context.Context, input repository.CreateRefreshTokenInput) (string, error) {
	return "mock-refresh-token", nil
}
func (m *MockTokenRepo) GetByHash(ctx context.Context, tokenHash string) (*repository.RefreshToken, error) {
	return nil, repository.ErrNotFound
}
func (m *MockTokenRepo) Revoke(ctx context.Context, tokenID string) error { return nil }
func (m *MockTokenRepo) GetFamilyRoot(ctx context.Context, tokenID string) (string, error) {
	return tokenID, nil
}
func (m *MockTokenRepo) RevokeFamily(ctx context.Context, familyRootID string) error { return nil }
func (m *MockTokenRepo) RevokeAllByUser(ctx context.Context, userID, clientID string) (int, error) {
	return 0, nil
}
func (m *MockTokenRepo) RevokeAllByClient(ctx context.Context, clientID string) error { return nil }
func (m *MockTokenRepo) GetByID(ctx context.Context, tokenID string) (*repository.RefreshToken, error) {
	return nil, repository.ErrNotFound
}
func (m *MockTokenRepo) List(ctx context.Context, filter repository.ListTokensFilter) ([]repository.RefreshToken, error) {
	return nil, nil
}
func (m *MockTokenRepo) Count(ctx context.Context, filter repository.ListTokensFilter) (int, error) {
	return 0, nil
}
func (m *MockTokenRepo) RevokeAll(ctx context.Context) (int, error) {
	return 0, nil
}
func (m *MockTokenRepo) GetStats(ctx context.Context) (*repository.TokenStats, error) {
	return &repository.TokenStats{}, nil
}

// MockClientRepo
type MockClientRepo struct{}

func (m *MockClientRepo) Get(ctx context.Context, clientID string) (*repository.Client, error) {
	return nil, repository.ErrNotFound
}
func (m *MockClientRepo) GetByUUID(ctx context.Context, uuid string) (*repository.Client, *repository.ClientVersion, error) {
	return nil, nil, repository.ErrNotFound
}
func (m *MockClientRepo) List(ctx context.Context, query string) ([]repository.Client, error) {
	return nil, nil
}
func (m *MockClientRepo) Create(ctx context.Context, input repository.ClientInput) (*repository.Client, error) {
	return nil, nil
}
func (m *MockClientRepo) Update(ctx context.Context, input repository.ClientInput) (*repository.Client, error) {
	return nil, nil
}
func (m *MockClientRepo) Delete(ctx context.Context, clientID string) error { return nil }
func (m *MockClientRepo) DecryptSecret(ctx context.Context, clientID string) (string, error) {
	return "", nil
}
func (m *MockClientRepo) ValidateClientID(id string) bool     { return true }
func (m *MockClientRepo) ValidateRedirectURI(uri string) bool { return true }
func (m *MockClientRepo) IsScopeAllowed(client *repository.Client, scope string) bool {
	return true
}

// MockMFARepo
type MockMFARepo struct{}

func (m *MockMFARepo) UpsertTOTP(ctx context.Context, userID, secretEnc string) error { return nil }
func (m *MockMFARepo) ConfirmTOTP(ctx context.Context, userID string) error           { return nil }
func (m *MockMFARepo) GetTOTP(ctx context.Context, userID string) (*repository.MFATOTP, error) {
	return nil, repository.ErrNotFound
}
func (m *MockMFARepo) UpdateTOTPUsedAt(ctx context.Context, userID string) error { return nil }
func (m *MockMFARepo) DisableTOTP(ctx context.Context, userID string) error      { return nil }
func (m *MockMFARepo) SetRecoveryCodes(ctx context.Context, userID string, hashes []string) error {
	return nil
}
func (m *MockMFARepo) DeleteRecoveryCodes(ctx context.Context, userID string) error { return nil }
func (m *MockMFARepo) UseRecoveryCode(ctx context.Context, userID, hash string) (bool, error) {
	return false, nil
}
func (m *MockMFARepo) AddTrustedDevice(ctx context.Context, userID, deviceHash string, expiresAt time.Time) error {
	return nil
}
func (m *MockMFARepo) IsTrustedDevice(ctx context.Context, userID, deviceHash string) (bool, error) {
	return false, nil
}

// ─── Admin Bootstrap ───

// seedFirstAdmin inserts the first super-admin into cp_admin when the table is
// empty. It is safe to call on every startup: it's a no-op once any admin exists.
// Activated by ADMIN_SEED_EMAIL + ADMIN_SEED_PASSWORD env vars (dev only).
func seedFirstAdmin(ctx context.Context, pool *pgxpool.Pool, email, password string) error {
	var count int
	if err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM cp_admin").Scan(&count); err != nil {
		return fmt.Errorf("count cp_admin: %w", err)
	}
	if count > 0 {
		log.Printf("[wiring] admin seed skipped — cp_admin already has %d admin(s)", count)
		return nil
	}
	hash, err := pwd.Hash(pwd.Default, password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO cp_admin (email, password_hash, name, role) VALUES ($1, $2, $3, 'global')`,
		email, hash, email,
	)
	if err != nil {
		return fmt.Errorf("insert admin: %w", err)
	}
	log.Printf("[wiring] 🌱 First admin seeded: %s", email)
	return nil
}
