// Package admin contiene los services administrativos V2.
package admin

import (
	"embed"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	controlplane "github.com/dropDatabas3/hellojohn/internal/controlplane"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	emailv2 "github.com/dropDatabas3/hellojohn/internal/email"
	"github.com/dropDatabas3/hellojohn/internal/jwt"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// Deps contiene las dependencias para crear los services admin.
type Deps struct {
	DAL                         store.DataAccessLayer
	ControlPlane                controlplane.Service
	Email                       emailv2.Service
	SystemEmail                 emailv2.SystemEmailService // SMTP global para invites de admin (opcional)
	MasterKey                   string
	Issuer                      *jwt.Issuer
	RefreshTTL                  time.Duration // TTL para admin refresh tokens
	BaseURL                     string        // Base URL for email verification links
	UIBaseURL                   string        // Frontend base URL for invite links
	SMSGlobalProvider           string
	GlobalTOTPIssuer            string
	GlobalTOTPWindow            int
	MFAAdaptiveEnabled          bool
	MFAAdaptiveRules            []string
	MFAAdaptiveFailureThreshold int
	MFAAdaptiveStateTTL         time.Duration
	AuditBus                    *audit.AuditBus
	TenantMigrationsFS          embed.FS // Tenant schema migrations for isolated DB
	TenantMigrationsDir         string   // Directory within TenantMigrationsFS
	// Optional: only populated when a global DB is configured
	UsageRepo  repository.UsageRepository       // nil → usage not available
	EtlJobRepo repository.MigrationJobRepository // nil → ETL not available
}

// Services agrupa todos los services del dominio admin.
type Services struct {
	Auth          AuthService
	Admins        AdminsService
	Clients       ClientService
	Consents      ConsentService
	Users         UserActionService
	UserCRUD      UserCRUDService
	Invitation    InvitationService
	Scopes        ScopeService
	Claims        ClaimsService
	RBAC          RBACService
	Tenants       TenantsService
	TokensAdmin   TokensAdminService
	SessionsAdmin *SessionsService
	Keys          KeysService
	APIKey        APIKeyService
	MFAStatus     MFAStatusService
	MFAConfig     MFAConfigService
	Cluster       ClusterService
	Audit         AuditService
	Import        ImportService
	Export        ExportService
	Migrate       MigrateService
	Usage         UsageService
	Etl           EtlService
	ControlPlane  controlplane.Service // Exportar ControlPlane
}

// NewServices crea el agregador de services admin.
func NewServices(d Deps) Services {
	return Services{
		Auth: NewAuthService(AuthServiceDeps{
			ControlPlane: d.ControlPlane,
			Issuer:       d.Issuer,
			RefreshTTL:   d.RefreshTTL,
			AuditBus:     d.AuditBus,
		}),
		Admins:   NewAdminsService(AdminsDeps{ControlPlane: d.ControlPlane, BaseURL: d.BaseURL, UIBaseURL: d.UIBaseURL, SystemEmail: d.SystemEmail}),
		Clients:  NewClientService(d.DAL, d.ControlPlane, d.AuditBus),
		Consents: NewConsentService(),
		Users:    NewUserActionService(d.Email, d.BaseURL, d.AuditBus),
		UserCRUD: NewUserCRUDService(UserCRUDDeps{
			DAL:      d.DAL,
			AuditBus: d.AuditBus,
		}),
		Invitation:    NewInvitationService(InvitationDeps{DAL: d.DAL}),
		Scopes:        NewScopeService(d.ControlPlane),
		Claims:        NewClaimsService(d.ControlPlane),
		RBAC:          NewRBACService(d.AuditBus),
		Tenants:       NewTenantsService(d.DAL, d.MasterKey, d.Issuer, d.Email, d.BaseURL, d.AuditBus),
		TokensAdmin:   NewTokensAdminService(TokensAdminDeps{DAL: d.DAL}),
		SessionsAdmin: NewSessionsService(d.DAL),
		Keys:          NewKeysService(d.DAL),
		APIKey:        NewAPIKeyService(APIKeyDeps{Repo: d.DAL.ConfigAccess().APIKeys()}),
		MFAStatus: NewMFAStatusService(MFAStatusDeps{
			DAL:                      d.DAL,
			SMSGlobalProvider:        d.SMSGlobalProvider,
			AdaptiveEnabled:          d.MFAAdaptiveEnabled,
			AdaptiveRules:            d.MFAAdaptiveRules,
			AdaptiveFailureThreshold: d.MFAAdaptiveFailureThreshold,
		}),
		MFAConfig: NewMFAConfigService(MFAConfigDeps{
			DAL:                     d.DAL,
			GlobalSMSProvider:       d.SMSGlobalProvider,
			GlobalTOTPIssuer:        d.GlobalTOTPIssuer,
			GlobalTOTPWindow:        d.GlobalTOTPWindow,
			GlobalAdaptiveEnabled:   d.MFAAdaptiveEnabled,
			GlobalAdaptiveRules:     d.MFAAdaptiveRules,
			GlobalAdaptiveThreshold: d.MFAAdaptiveFailureThreshold,
			GlobalAdaptiveStateTTL:  d.MFAAdaptiveStateTTL,
		}),
		Cluster:      NewClusterService(ClusterDeps{DAL: d.DAL}),
		Audit:        NewAuditService(d.DAL, d.AuditBus),
		Import:       NewImportService(ImportDeps{DAL: d.DAL}),
		Export:       NewExportService(ExportDeps{DAL: d.DAL}),
		Migrate:      NewMigrateService(MigrateServiceDeps{DAL: d.DAL, ControlPlane: d.ControlPlane, TenantMigrations: d.TenantMigrationsFS, TenantMigrDir: d.TenantMigrationsDir}),
		Usage:        NewUsageService(d.UsageRepo),
		Etl:          NewEtlService(EtlDeps{DAL: d.DAL, JobRepo: d.EtlJobRepo, BaseURL: d.BaseURL}),
		ControlPlane: d.ControlPlane,
	}
}
