package social

import (
	"context"

	cache "github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

type socialDALStub struct {
	tda store.TenantDataAccess
	err error
}

func (d *socialDALStub) ForTenant(context.Context, string) (store.TenantDataAccess, error) {
	if d.err != nil {
		return nil, d.err
	}
	return d.tda, nil
}

func (d *socialDALStub) ConfigAccess() store.ConfigAccess { return nil }
func (d *socialDALStub) Mode() store.OperationalMode      { return store.ModeFSTenantDB }
func (d *socialDALStub) Capabilities() store.ModeCapabilities {
	return store.GetCapabilities(store.ModeFSTenantDB)
}
func (d *socialDALStub) Stats() store.FactoryStats             { return store.FactoryStats{} }
func (d *socialDALStub) Cluster() repository.ClusterRepository { return nil }
func (d *socialDALStub) MigrateTenant(context.Context, string) (*store.MigrationResult, error) {
	return nil, nil
}
func (d *socialDALStub) InvalidateTenantCache(string) {}
func (d *socialDALStub) Close() error                 { return nil }

type socialTDAStub struct {
	slug         string
	id           string
	settings     *repository.TenantSettings
	requireDBErr error
	users        repository.UserRepository
	tokens       repository.TokenRepository
	identities   repository.IdentityRepository
	clients      repository.ClientRepository
	scopes       repository.ScopeRepository
	cache        cache.Client
	cacheRepo    repository.CacheRepository
}

func (t *socialTDAStub) Slug() string { return t.slug }
func (t *socialTDAStub) ID() string   { return t.id }
func (t *socialTDAStub) Settings() *repository.TenantSettings {
	if t.settings != nil {
		return t.settings
	}
	return &repository.TenantSettings{}
}
func (t *socialTDAStub) Driver() string                               { return "test" }
func (t *socialTDAStub) Users() repository.UserRepository             { return t.users }
func (t *socialTDAStub) Tokens() repository.TokenRepository           { return t.tokens }
func (t *socialTDAStub) MFA() repository.MFARepository                { return nil }
func (t *socialTDAStub) Consents() repository.ConsentRepository       { return nil }
func (t *socialTDAStub) RBAC() repository.RBACRepository              { return nil }
func (t *socialTDAStub) Schema() repository.SchemaRepository          { return nil }
func (t *socialTDAStub) EmailTokens() repository.EmailTokenRepository { return nil }
func (t *socialTDAStub) Identities() repository.IdentityRepository    { return t.identities }
func (t *socialTDAStub) Sessions() repository.SessionRepository       { return nil }
func (t *socialTDAStub) Clients() repository.ClientRepository         { return t.clients }
func (t *socialTDAStub) Scopes() repository.ScopeRepository           { return t.scopes }
func (t *socialTDAStub) Cache() cache.Client                          { return t.cache }
func (t *socialTDAStub) CacheRepo() repository.CacheRepository        { return t.cacheRepo }
func (t *socialTDAStub) Mailer() store.MailSender                     { return nil }
func (t *socialTDAStub) Invitations() repository.InvitationRepository { return nil }
func (t *socialTDAStub) WebAuthn() repository.WebAuthnRepository      { return nil }
func (t *socialTDAStub) InfraStats(context.Context) (*store.TenantInfraStats, error) {
	return nil, nil
}
func (t *socialTDAStub) HasDB() bool { return t.requireDBErr == nil }
func (t *socialTDAStub) RequireDB() error {
	return t.requireDBErr
}
func (t *socialTDAStub) Audit() repository.AuditRepository      { return nil }
func (t *socialTDAStub) Claims() repository.ClaimRepository     { return nil }
func (t *socialTDAStub) Webhooks() repository.WebhookRepository { return nil }
