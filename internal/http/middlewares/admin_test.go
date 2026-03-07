package middlewares

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/jwt"
	obslog "github.com/dropDatabas3/hellojohn/internal/observability/logger"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestRequireAdminTenantAccess_DeniedLogRedactsSensitiveFields(t *testing.T) {
	core, recorded := observer.New(zap.DebugLevel)
	reqLogger := zap.New(core)

	req := httptest.NewRequest(http.MethodGet, "/v2/admin/tenants/tenant-b/users?tenant_id=tenant-b", nil)
	ctx := obslog.ToContext(req.Context(), reqLogger)
	ctx = SetAdminClaims(ctx, &jwt.AdminAccessClaims{
		AdminID:   "admin-1",
		Email:     "admin@example.com",
		AdminType: "tenant",
		Tenants:   []jwt.TenantAccessClaim{{Slug: "tenant-a", Role: "owner"}},
	})
	req = req.WithContext(ctx)

	nextCalled := false
	handler := RequireAdminTenantAccess()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if nextCalled {
		t.Fatalf("expected request to be denied before next handler")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}

	denied := recorded.FilterMessage("admin tenant access denied").All()
	if len(denied) == 0 {
		t.Fatalf("expected denial log entry")
	}

	fields := denied[0].ContextMap()
	if _, ok := fields["admin_email"]; ok {
		t.Fatalf("sensitive field admin_email must not be logged")
	}
	if _, ok := fields["allowed_tenants"]; ok {
		t.Fatalf("sensitive field allowed_tenants must not be logged")
	}
	if got, ok := fields["admin_id"]; !ok || got != "admin-1" {
		t.Fatalf("expected admin_id=admin-1, got %v", got)
	}
	if got, ok := fields["requested_tenant"]; !ok || got != "tenant-b" {
		t.Fatalf("expected requested_tenant=tenant-b, got %v", got)
	}
	if got, ok := fields["allowed_tenants_count"]; !ok || (got != 1 && got != int64(1)) {
		t.Fatalf("expected allowed_tenants_count=1, got %v", got)
	}

	for _, entry := range recorded.All() {
		if strings.Contains(entry.Message, "admin@example.com") {
			t.Fatalf("log message leaked email: %s", entry.Message)
		}
		for _, f := range entry.Context {
			if strings.Contains(f.String, "admin@example.com") {
				t.Fatalf("log field leaked email")
			}
			if strings.Contains(f.String, "tenant-a") {
				t.Fatalf("log field leaked allowed tenant list")
			}
		}
	}
}

type fakeAdminTenantTDA struct {
	slug string
	id   string
}

func (f *fakeAdminTenantTDA) Slug() string                                 { return f.slug }
func (f *fakeAdminTenantTDA) ID() string                                   { return f.id }
func (f *fakeAdminTenantTDA) Settings() *repository.TenantSettings         { return nil }
func (f *fakeAdminTenantTDA) Driver() string                               { return "test" }
func (f *fakeAdminTenantTDA) Users() repository.UserRepository             { return nil }
func (f *fakeAdminTenantTDA) Tokens() repository.TokenRepository           { return nil }
func (f *fakeAdminTenantTDA) MFA() repository.MFARepository                { return nil }
func (f *fakeAdminTenantTDA) Consents() repository.ConsentRepository       { return nil }
func (f *fakeAdminTenantTDA) RBAC() repository.RBACRepository              { return nil }
func (f *fakeAdminTenantTDA) Schema() repository.SchemaRepository          { return nil }
func (f *fakeAdminTenantTDA) EmailTokens() repository.EmailTokenRepository { return nil }
func (f *fakeAdminTenantTDA) Identities() repository.IdentityRepository    { return nil }
func (f *fakeAdminTenantTDA) Sessions() repository.SessionRepository       { return nil }
func (f *fakeAdminTenantTDA) Audit() repository.AuditRepository            { return nil }
func (f *fakeAdminTenantTDA) Claims() repository.ClaimRepository           { return nil }
func (f *fakeAdminTenantTDA) Webhooks() repository.WebhookRepository       { return nil }
func (f *fakeAdminTenantTDA) Clients() repository.ClientRepository         { return nil }
func (f *fakeAdminTenantTDA) Scopes() repository.ScopeRepository           { return nil }
func (f *fakeAdminTenantTDA) Cache() cache.Client                          { return nil }
func (f *fakeAdminTenantTDA) CacheRepo() repository.CacheRepository        { return nil }
func (f *fakeAdminTenantTDA) Mailer() store.MailSender                     { return nil }
func (f *fakeAdminTenantTDA) Invitations() repository.InvitationRepository { return nil }
func (f *fakeAdminTenantTDA) WebAuthn() repository.WebAuthnRepository      { return nil }
func (f *fakeAdminTenantTDA) HasDB() bool                                  { return true }
func (f *fakeAdminTenantTDA) RequireDB() error                             { return nil }
func (f *fakeAdminTenantTDA) InfraStats(_ context.Context) (*store.TenantInfraStats, error) {
	return nil, nil
}

func TestRequireAdminTenantAccess_AllowsClaimsIDWhenRequestUsesSlug(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v2/admin/tenants/acme/users?tenant_id=acme", nil)
	ctx := SetAdminClaims(req.Context(), &jwt.AdminAccessClaims{
		AdminID:   "admin-1",
		AdminType: "tenant",
		Tenants:   []jwt.TenantAccessClaim{{Slug: "tenant-123", Role: "owner"}},
	})
	ctx = WithTenant(ctx, &fakeAdminTenantTDA{slug: "acme", id: "tenant-123"})
	req = req.WithContext(ctx)

	nextCalled := false
	handler := RequireAdminTenantAccess()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !nextCalled {
		t.Fatalf("expected request to be allowed")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestRequireAdminTenantAccess_AllowsClaimsSlugWhenRequestUsesID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v2/admin/tenants/tenant-123/users?tenant_id=tenant-123", nil)
	ctx := SetAdminClaims(req.Context(), &jwt.AdminAccessClaims{
		AdminID:   "admin-1",
		AdminType: "tenant",
		Tenants:   []jwt.TenantAccessClaim{{Slug: "acme", Role: "owner"}},
	})
	ctx = WithTenant(ctx, &fakeAdminTenantTDA{slug: "acme", id: "tenant-123"})
	req = req.WithContext(ctx)

	nextCalled := false
	handler := RequireAdminTenantAccess()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !nextCalled {
		t.Fatalf("expected request to be allowed")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestRequireAdminTenantAccess_DeniesWhenQueryTenantConflictsWithCanonicalContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v2/admin/tenants/acme/users?tenant_id=tenant-evil", nil)
	ctx := SetAdminClaims(req.Context(), &jwt.AdminAccessClaims{
		AdminID:   "admin-1",
		AdminType: "tenant",
		// Solo coincide con query manipulada, NO con tenant canonico del contexto.
		Tenants: []jwt.TenantAccessClaim{{Slug: "tenant-evil", Role: "owner"}},
	})
	ctx = WithTenant(ctx, &fakeAdminTenantTDA{slug: "acme", id: "tenant-123"})
	req = req.WithContext(ctx)

	nextCalled := false
	handler := RequireAdminTenantAccess()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if nextCalled {
		t.Fatalf("expected request to be denied")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, rr.Code)
	}
}
