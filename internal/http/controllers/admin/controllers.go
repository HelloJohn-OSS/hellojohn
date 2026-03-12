// Package admin contiene los controllers administrativos V2.
package admin

import (
	"github.com/dropDatabas3/hellojohn/internal/controlplane"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// Controllers agrupa todos los controllers del dominio admin.
type Controllers struct {
	Auth        *AuthController
	Admins      *AdminsController
	Clients     *ClientsController
	Consents    *ConsentsController
	Users       *UsersController
	UsersCRUD   *UsersCRUDController
	Invitation  *InvitationController
	Scopes      *ScopesController
	Claims      *ClaimsController
	RBAC        *RBACController
	Tenants     *TenantsController
	Webhooks    *WebhooksController
	Tokens      *TokensController
	Sessions    *SessionsController
	Keys        *KeysController
	APIKey      *APIKeyController
	MFAStatus   *MFAStatusController
	MFAConfig   *MFAConfigController
	Cluster     *ClusterController
	Audit       *AuditController
	Import      *ImportController
	Export      *ExportController
	Migrate     *MigrateController
	Usage       *UsageController
	Etl         *EtlController
	SystemEmail *SystemEmailController
}

// ControllerDeps contiene dependencias adicionales para controllers.
type ControllerDeps struct {
	DAL                     store.DataAccessLayer
	ControlPlane            controlplane.Service
	KeyRotationGraceSeconds int64
}

// NewControllers crea el agregador de controllers admin.
func NewControllers(s svc.Services, deps ControllerDeps) *Controllers {
	return &Controllers{
		Auth:     NewAuthController(s.Auth),
		Admins:   NewAdminsController(s.Admins),
		Clients:  NewClientsController(s.Clients),
		Consents: NewConsentsController(s.Consents),
		Users:    NewUsersController(s.Users),
		// UsersCRUD ahora recibe actionService y DAL para soportar acciones tenant-scoped
		UsersCRUD:   NewUsersCRUDControllerWithActions(s.UserCRUD, s.Users, deps.DAL),
		Invitation:  NewInvitationController(s.Invitation),
		Scopes:      NewScopesController(s.Scopes),
		Claims:      NewClaimsController(s.Claims),
		RBAC:        NewRBACController(s.RBAC),
		Tenants:     NewTenantsController(s.Tenants, deps.KeyRotationGraceSeconds),
		Webhooks:    NewWebhooksController(deps.ControlPlane), // Instanciación nativa pasándole CP
		Tokens:      NewTokensController(s.TokensAdmin),
		Sessions:    NewSessionsController(s.SessionsAdmin),
		Keys:        NewKeysController(s.Keys),
		APIKey:      NewAPIKeyController(s.APIKey),
		MFAStatus:   NewMFAStatusController(s.MFAStatus),
		MFAConfig:   NewMFAConfigController(s.MFAConfig),
		Cluster:     NewClusterController(s.Cluster),
		Audit:       NewAuditController(s.Audit),
		Import:      NewImportController(s.Import),
		Export:      NewExportController(s.Export),
		Migrate:     NewMigrateController(s.Migrate),
		Usage:       NewUsageController(s.Usage),
		Etl:         NewEtlController(s.Etl),
		SystemEmail: NewSystemEmailController(s.SystemEmailCP),
	}
}
