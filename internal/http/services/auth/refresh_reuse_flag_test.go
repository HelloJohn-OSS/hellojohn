package auth

import (
	"context"
	"testing"
	"time"

	cache "github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

type fakeDAL struct {
	tda store.TenantDataAccess
}

func (d *fakeDAL) ForTenant(context.Context, string) (store.TenantDataAccess, error) {
	return d.tda, nil
}
func (d *fakeDAL) ConfigAccess() store.ConfigAccess { return nil }
func (d *fakeDAL) Mode() store.OperationalMode      { return store.ModeFSTenantDB }
func (d *fakeDAL) Capabilities() store.ModeCapabilities {
	return store.GetCapabilities(store.ModeFSTenantDB)
}
func (d *fakeDAL) Stats() store.FactoryStats             { return store.FactoryStats{} }
func (d *fakeDAL) Cluster() repository.ClusterRepository { return nil }
func (d *fakeDAL) MigrateTenant(context.Context, string) (*store.MigrationResult, error) {
	return nil, nil
}
func (d *fakeDAL) InvalidateTenantCache(string) {}
func (d *fakeDAL) Close() error                 { return nil }

type fakeTDA struct {
	slug   string
	id     string
	tokens repository.TokenRepository
}

func (t *fakeTDA) Slug() string                                 { return t.slug }
func (t *fakeTDA) ID() string                                   { return t.id }
func (t *fakeTDA) Settings() *repository.TenantSettings         { return &repository.TenantSettings{} }
func (t *fakeTDA) Driver() string                               { return "test" }
func (t *fakeTDA) Users() repository.UserRepository             { return nil }
func (t *fakeTDA) Tokens() repository.TokenRepository           { return t.tokens }
func (t *fakeTDA) MFA() repository.MFARepository                { return nil }
func (t *fakeTDA) Consents() repository.ConsentRepository       { return nil }
func (t *fakeTDA) RBAC() repository.RBACRepository              { return nil }
func (t *fakeTDA) Schema() repository.SchemaRepository          { return nil }
func (t *fakeTDA) EmailTokens() repository.EmailTokenRepository { return nil }
func (t *fakeTDA) Identities() repository.IdentityRepository    { return nil }
func (t *fakeTDA) Sessions() repository.SessionRepository       { return nil }
func (t *fakeTDA) Clients() repository.ClientRepository         { return nil }
func (t *fakeTDA) Scopes() repository.ScopeRepository           { return nil }
func (t *fakeTDA) Cache() cache.Client                          { return nil }
func (t *fakeTDA) CacheRepo() repository.CacheRepository        { return nil }
func (t *fakeTDA) Mailer() store.MailSender                     { return nil }
func (t *fakeTDA) Invitations() repository.InvitationRepository { return nil }
func (t *fakeTDA) WebAuthn() repository.WebAuthnRepository      { return nil }
func (t *fakeTDA) InfraStats(context.Context) (*store.TenantInfraStats, error) {
	return nil, nil
}
func (t *fakeTDA) HasDB() bool                            { return true }
func (t *fakeTDA) RequireDB() error                       { return nil }
func (t *fakeTDA) Audit() repository.AuditRepository      { return nil }
func (t *fakeTDA) Claims() repository.ClaimRepository     { return nil }
func (t *fakeTDA) Webhooks() repository.WebhookRepository { return nil }

type fakeTokenRepo struct {
	token              *repository.RefreshToken
	familyRootID       string
	getFamilyRootCalls int
	revokeFamilyCalls  int
}

func (r *fakeTokenRepo) Create(context.Context, repository.CreateRefreshTokenInput) (string, error) {
	return "", nil
}
func (r *fakeTokenRepo) GetByHash(context.Context, string) (*repository.RefreshToken, error) {
	return r.token, nil
}
func (r *fakeTokenRepo) GetByID(context.Context, string) (*repository.RefreshToken, error) {
	return nil, repository.ErrNotFound
}
func (r *fakeTokenRepo) Revoke(context.Context, string) error { return nil }
func (r *fakeTokenRepo) GetFamilyRoot(context.Context, string) (string, error) {
	r.getFamilyRootCalls++
	return r.familyRootID, nil
}
func (r *fakeTokenRepo) RevokeFamily(context.Context, string) error {
	r.revokeFamilyCalls++
	return nil
}
func (r *fakeTokenRepo) RevokeAllByUser(context.Context, string, string) (int, error) { return 0, nil }
func (r *fakeTokenRepo) RevokeAllByClient(context.Context, string) error              { return nil }
func (r *fakeTokenRepo) List(context.Context, repository.ListTokensFilter) ([]repository.RefreshToken, error) {
	return nil, nil
}
func (r *fakeTokenRepo) Count(context.Context, repository.ListTokensFilter) (int, error) {
	return 0, nil
}
func (r *fakeTokenRepo) RevokeAll(context.Context) (int, error)                   { return 0, nil }
func (r *fakeTokenRepo) GetStats(context.Context) (*repository.TokenStats, error) { return nil, nil }

func TestRefreshRevokedTokenReuseDetectionFlag(t *testing.T) {
	t.Parallel()

	revokedAt := time.Now().UTC()
	repo := &fakeTokenRepo{
		token: &repository.RefreshToken{
			ID:        "rt-1",
			UserID:    "user-1",
			TenantID:  "tenant-a",
			ClientID:  "client-a",
			ExpiresAt: time.Now().Add(1 * time.Hour),
			RevokedAt: &revokedAt,
		},
		familyRootID: "root-1",
	}
	tda := &fakeTDA{
		slug:   "tenant-a",
		id:     "tenant-a",
		tokens: repo,
	}
	dal := &fakeDAL{tda: tda}
	issuer := &jwtx.Issuer{AccessTTL: 15 * time.Minute}

	svcWithReuse := NewRefreshService(RefreshDeps{
		DAL:                   dal,
		Issuer:                issuer,
		RefreshTTL:            30 * 24 * time.Hour,
		ReuseDetectionEnabled: true,
	})

	_, err := svcWithReuse.Refresh(context.Background(), dto.RefreshRequest{
		TenantID:     "tenant-a",
		ClientID:     "client-a",
		RefreshToken: "opaque-refresh-token",
	}, "")
	if err != ErrRefreshTokenReuse {
		t.Fatalf("expected ErrRefreshTokenReuse, got %v", err)
	}
	if repo.getFamilyRootCalls != 1 || repo.revokeFamilyCalls != 1 {
		t.Fatalf("expected family revoke flow, got rootCalls=%d revokeCalls=%d", repo.getFamilyRootCalls, repo.revokeFamilyCalls)
	}

	repo.getFamilyRootCalls = 0
	repo.revokeFamilyCalls = 0

	svcWithoutReuse := NewRefreshService(RefreshDeps{
		DAL:                   dal,
		Issuer:                issuer,
		RefreshTTL:            30 * 24 * time.Hour,
		ReuseDetectionEnabled: false,
	})
	_, err = svcWithoutReuse.Refresh(context.Background(), dto.RefreshRequest{
		TenantID:     "tenant-a",
		ClientID:     "client-a",
		RefreshToken: "opaque-refresh-token",
	}, "")
	if err != ErrRefreshTokenRevoked {
		t.Fatalf("expected ErrRefreshTokenRevoked, got %v", err)
	}
	if repo.getFamilyRootCalls != 0 || repo.revokeFamilyCalls != 0 {
		t.Fatalf("family revoke should be skipped when feature flag is off")
	}
}
