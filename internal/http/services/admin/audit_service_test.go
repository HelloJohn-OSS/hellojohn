package admin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

type auditServiceDALStub struct {
	tda store.TenantDataAccess
	err error
}

func (d *auditServiceDALStub) ForTenant(ctx context.Context, slugOrID string) (store.TenantDataAccess, error) {
	if d.err != nil {
		return nil, d.err
	}
	return d.tda, nil
}
func (d *auditServiceDALStub) ConfigAccess() store.ConfigAccess { return nil }
func (d *auditServiceDALStub) Mode() store.OperationalMode      { return store.ModeFSTenantDB }
func (d *auditServiceDALStub) Capabilities() store.ModeCapabilities {
	return store.GetCapabilities(store.ModeFSTenantDB)
}
func (d *auditServiceDALStub) Stats() store.FactoryStats             { return store.FactoryStats{} }
func (d *auditServiceDALStub) Cluster() repository.ClusterRepository { return nil }
func (d *auditServiceDALStub) MigrateTenant(ctx context.Context, slugOrID string) (*store.MigrationResult, error) {
	return nil, nil
}
func (d *auditServiceDALStub) InvalidateTenantCache(string) {}
func (d *auditServiceDALStub) Close() error                 { return nil }

type auditServiceTDAStub struct {
	slug         string
	id           string
	requireDBErr error
	auditRepo    repository.AuditRepository
}

func (t *auditServiceTDAStub) Slug() string                         { return t.slug }
func (t *auditServiceTDAStub) ID() string                           { return t.id }
func (t *auditServiceTDAStub) Settings() *repository.TenantSettings { return nil }
func (t *auditServiceTDAStub) Driver() string                       { return "test" }
func (t *auditServiceTDAStub) Users() repository.UserRepository     { return nil }
func (t *auditServiceTDAStub) Tokens() repository.TokenRepository   { return nil }
func (t *auditServiceTDAStub) MFA() repository.MFARepository        { return nil }
func (t *auditServiceTDAStub) Consents() repository.ConsentRepository {
	return nil
}
func (t *auditServiceTDAStub) RBAC() repository.RBACRepository              { return nil }
func (t *auditServiceTDAStub) Schema() repository.SchemaRepository          { return nil }
func (t *auditServiceTDAStub) EmailTokens() repository.EmailTokenRepository { return nil }
func (t *auditServiceTDAStub) Identities() repository.IdentityRepository    { return nil }
func (t *auditServiceTDAStub) Sessions() repository.SessionRepository       { return nil }
func (t *auditServiceTDAStub) Audit() repository.AuditRepository            { return t.auditRepo }
func (t *auditServiceTDAStub) Claims() repository.ClaimRepository           { return nil }
func (t *auditServiceTDAStub) Webhooks() repository.WebhookRepository       { return nil }
func (t *auditServiceTDAStub) Clients() repository.ClientRepository         { return nil }
func (t *auditServiceTDAStub) Scopes() repository.ScopeRepository           { return nil }
func (t *auditServiceTDAStub) Cache() cache.Client                          { return nil }
func (t *auditServiceTDAStub) CacheRepo() repository.CacheRepository        { return nil }
func (t *auditServiceTDAStub) Mailer() store.MailSender                     { return nil }
func (t *auditServiceTDAStub) Invitations() repository.InvitationRepository { return nil }
func (t *auditServiceTDAStub) WebAuthn() repository.WebAuthnRepository      { return nil }
func (t *auditServiceTDAStub) InfraStats(ctx context.Context) (*store.TenantInfraStats, error) {
	return nil, nil
}
func (t *auditServiceTDAStub) HasDB() bool {
	return t.requireDBErr == nil
}
func (t *auditServiceTDAStub) RequireDB() error { return t.requireDBErr }

type auditRepoStub struct {
	purgeDeleted int64
	purgeErr     error
}

func (r *auditRepoStub) InsertBatch(ctx context.Context, events []audit.AuditEvent) error { return nil }
func (r *auditRepoStub) List(ctx context.Context, filter repository.AuditFilter) ([]audit.AuditEvent, int64, error) {
	return nil, 0, nil
}
func (r *auditRepoStub) GetByID(ctx context.Context, id string) (*audit.AuditEvent, error) {
	return nil, nil
}
func (r *auditRepoStub) Purge(ctx context.Context, before time.Time) (int64, error) {
	return r.purgeDeleted, r.purgeErr
}

func newAuditServiceForTest(dal store.DataAccessLayer) (AuditService, *audit.AuditBus, *captureAuditWriter) {
	writer := &captureAuditWriter{}
	bus := audit.NewAuditBus(writer)
	bus.Start()
	return NewAuditService(dal, bus), bus, writer
}

func findAuditPurgeEvent(t *testing.T, events []audit.AuditEvent) audit.AuditEvent {
	t.Helper()
	for _, e := range events {
		if e.Type == audit.EventAuditPurged {
			return e
		}
	}
	t.Fatalf("expected %q event, got %d events", audit.EventAuditPurged, len(events))
	return audit.AuditEvent{}
}

func TestAuditServicePurge_ForTenantError_EmitsErrorEvent(t *testing.T) {
	t.Parallel()

	before := time.Now().UTC().Add(-24 * time.Hour)
	dal := &auditServiceDALStub{err: errors.New("tenant lookup failed")}
	svc, bus, writer := newAuditServiceForTest(dal)
	defer bus.Stop()

	if _, err := svc.Purge(context.Background(), "acme", before); err == nil {
		t.Fatalf("expected error")
	}

	bus.Stop()
	evt := findAuditPurgeEvent(t, writer.Snapshot())
	if evt.Result != audit.ResultError {
		t.Fatalf("expected error result, got %q", evt.Result)
	}
	if evt.TenantID != audit.ControlPlaneTenantID {
		t.Fatalf("expected tenant id %q, got %q", audit.ControlPlaneTenantID, evt.TenantID)
	}
	if got := evt.Metadata["reason"]; got != "tenant_resolve_failed" {
		t.Fatalf("expected reason tenant_resolve_failed, got %v", got)
	}
	if got := evt.Metadata["tenant_ref_input"]; got != "acme" {
		t.Fatalf("expected tenant_ref_input acme, got %v", got)
	}
}

func TestAuditServicePurge_RequireDBError_EmitsErrorEvent(t *testing.T) {
	t.Parallel()

	before := time.Now().UTC().Add(-24 * time.Hour)
	tda := &auditServiceTDAStub{
		slug:         "acme",
		id:           "tenant-1",
		requireDBErr: errors.New("db unavailable"),
		auditRepo:    &auditRepoStub{},
	}
	dal := &auditServiceDALStub{tda: tda}
	svc, bus, writer := newAuditServiceForTest(dal)
	defer bus.Stop()

	if _, err := svc.Purge(context.Background(), "acme", before); err == nil {
		t.Fatalf("expected error")
	}

	bus.Stop()
	evt := findAuditPurgeEvent(t, writer.Snapshot())
	if evt.Result != audit.ResultError {
		t.Fatalf("expected error result, got %q", evt.Result)
	}
	if evt.TenantID != "tenant-1" {
		t.Fatalf("expected tenant id tenant-1, got %q", evt.TenantID)
	}
	if got := evt.Metadata["reason"]; got != "require_db_failed" {
		t.Fatalf("expected reason require_db_failed, got %v", got)
	}
}

func TestAuditServicePurge_PurgeRepoError_EmitsErrorEvent(t *testing.T) {
	t.Parallel()

	before := time.Now().UTC().Add(-24 * time.Hour)
	tda := &auditServiceTDAStub{
		slug:      "acme",
		id:        "tenant-1",
		auditRepo: &auditRepoStub{purgeErr: errors.New("purge failed")},
	}
	dal := &auditServiceDALStub{tda: tda}
	svc, bus, writer := newAuditServiceForTest(dal)
	defer bus.Stop()

	if _, err := svc.Purge(context.Background(), "acme", before); err == nil {
		t.Fatalf("expected error")
	}

	bus.Stop()
	evt := findAuditPurgeEvent(t, writer.Snapshot())
	if evt.Result != audit.ResultError {
		t.Fatalf("expected error result, got %q", evt.Result)
	}
	if got := evt.Metadata["reason"]; got != "purge_failed" {
		t.Fatalf("expected reason purge_failed, got %v", got)
	}
}

func TestAuditServicePurge_Success_EmitsSuccessEvent(t *testing.T) {
	t.Parallel()

	before := time.Now().UTC().Add(-24 * time.Hour)
	tda := &auditServiceTDAStub{
		slug:      "acme",
		id:        "tenant-1",
		auditRepo: &auditRepoStub{purgeDeleted: 7},
	}
	dal := &auditServiceDALStub{tda: tda}
	svc, bus, writer := newAuditServiceForTest(dal)
	defer bus.Stop()

	deleted, err := svc.Purge(context.Background(), "acme", before)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if deleted != 7 {
		t.Fatalf("expected deleted=7, got %d", deleted)
	}

	bus.Stop()
	evt := findAuditPurgeEvent(t, writer.Snapshot())
	if evt.Result != audit.ResultSuccess {
		t.Fatalf("expected success result, got %q", evt.Result)
	}
	if got := evt.Metadata["deleted_count"]; got != int64(7) {
		t.Fatalf("expected deleted_count=7, got %v", got)
	}
}
