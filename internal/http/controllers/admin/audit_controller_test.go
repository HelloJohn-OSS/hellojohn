package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// ───────────────────────── canReadAudit / canPurgeAudit ─────────────────────────

func TestCanReadAudit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		claims *jwtx.AdminAccessClaims
		want   bool
	}{
		{
			name:   "explicit audit read permission allowed",
			claims: &jwtx.AdminAccessClaims{Perms: []string{"audit:read"}},
			want:   true,
		},
		{
			name:   "audit wildcard permission allowed",
			claims: &jwtx.AdminAccessClaims{Perms: []string{"audit:*"}},
			want:   true,
		},
		{
			name:   "global wildcard permission allowed",
			claims: &jwtx.AdminAccessClaims{Perms: []string{"*"}},
			want:   true,
		},
		{
			name:   "only purge permission denied for read",
			claims: &jwtx.AdminAccessClaims{Perms: []string{"audit:purge"}},
			want:   false,
		},
		{
			name:   "empty perms denied",
			claims: &jwtx.AdminAccessClaims{Perms: nil},
			want:   false,
		},
		{
			name:   "nil claims denied",
			claims: nil,
			want:   false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := canReadAudit(tc.claims)
			if got != tc.want {
				t.Fatalf("canReadAudit() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCanPurgeAudit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		claims *jwtx.AdminAccessClaims
		want   bool
	}{
		{
			name:   "explicit purge permission allowed",
			claims: &jwtx.AdminAccessClaims{Perms: []string{"audit:purge"}},
			want:   true,
		},
		{
			name:   "audit wildcard permission allowed",
			claims: &jwtx.AdminAccessClaims{Perms: []string{"audit:*"}},
			want:   true,
		},
		{
			name:   "only read permission denied for purge",
			claims: &jwtx.AdminAccessClaims{Perms: []string{"audit:read"}},
			want:   false,
		},
		{
			name:   "nil claims denied",
			claims: nil,
			want:   false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := canPurgeAudit(tc.claims)
			if got != tc.want {
				t.Fatalf("canPurgeAudit() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ───────────────────────── Stub implementations ─────────────────────────

// stubAuditService is a minimal in-memory AuditService for controller tests.
type stubAuditService struct {
	events  []audit.AuditEvent
	total   int64
	single  *audit.AuditEvent
	deleted int64
	err     error
}

func (s *stubAuditService) List(_ context.Context, _ string, _ repository.AuditFilter) ([]audit.AuditEvent, int64, error) {
	return s.events, s.total, s.err
}
func (s *stubAuditService) GetByID(_ context.Context, _ string, _ string) (*audit.AuditEvent, error) {
	return s.single, s.err
}
func (s *stubAuditService) Purge(_ context.Context, _ string, _ time.Time) (int64, error) {
	return s.deleted, s.err
}

// fakeAuditTDA implements TenantDataAccess for controller context injection.
type fakeAuditTDA struct {
	slug string
	id   string
}

func (f *fakeAuditTDA) Slug() string                                 { return f.slug }
func (f *fakeAuditTDA) ID() string                                   { return f.id }
func (f *fakeAuditTDA) Settings() *repository.TenantSettings         { return nil }
func (f *fakeAuditTDA) Driver() string                               { return "test" }
func (f *fakeAuditTDA) Users() repository.UserRepository             { return nil }
func (f *fakeAuditTDA) Tokens() repository.TokenRepository           { return nil }
func (f *fakeAuditTDA) MFA() repository.MFARepository                { return nil }
func (f *fakeAuditTDA) Consents() repository.ConsentRepository       { return nil }
func (f *fakeAuditTDA) RBAC() repository.RBACRepository              { return nil }
func (f *fakeAuditTDA) Schema() repository.SchemaRepository          { return nil }
func (f *fakeAuditTDA) EmailTokens() repository.EmailTokenRepository { return nil }
func (f *fakeAuditTDA) Identities() repository.IdentityRepository    { return nil }
func (f *fakeAuditTDA) Sessions() repository.SessionRepository       { return nil }
func (f *fakeAuditTDA) Audit() repository.AuditRepository            { return nil }
func (f *fakeAuditTDA) Claims() repository.ClaimRepository           { return nil }
func (f *fakeAuditTDA) Webhooks() repository.WebhookRepository       { return nil }
func (f *fakeAuditTDA) Clients() repository.ClientRepository         { return nil }
func (f *fakeAuditTDA) Scopes() repository.ScopeRepository           { return nil }
func (f *fakeAuditTDA) Cache() cache.Client                          { return nil }
func (f *fakeAuditTDA) CacheRepo() repository.CacheRepository        { return nil }
func (f *fakeAuditTDA) Mailer() store.MailSender                     { return nil }
func (f *fakeAuditTDA) Invitations() repository.InvitationRepository { return nil }
func (f *fakeAuditTDA) WebAuthn() repository.WebAuthnRepository      { return nil }
func (f *fakeAuditTDA) HasDB() bool                                  { return true }
func (f *fakeAuditTDA) RequireDB() error                             { return nil }
func (f *fakeAuditTDA) InfraStats(_ context.Context) (*store.TenantInfraStats, error) {
	return nil, nil
}

// ctxWith builds a context with optional tenant + admin claims for controller tests.
func ctxWith(tda store.TenantDataAccess, claims *jwtx.AdminAccessClaims) context.Context {
	ctx := context.Background()
	if tda != nil {
		ctx = mw.WithTenant(ctx, tda)
	}
	if claims != nil {
		ctx = mw.SetAdminClaims(ctx, claims)
	}
	return ctx
}

func readClaims() *jwtx.AdminAccessClaims {
	return &jwtx.AdminAccessClaims{
		AdminType: "global",
		Perms:     []string{"audit:read"},
	}
}

func tenantReadClaims() *jwtx.AdminAccessClaims {
	return &jwtx.AdminAccessClaims{
		AdminType: "tenant",
		Perms:     []string{"audit:read"},
	}
}

func purgeClaims() *jwtx.AdminAccessClaims {
	return &jwtx.AdminAccessClaims{
		AdminType: "global",
		Perms:     []string{"audit:purge"},
	}
}

// ───────────────────────── List handler tests ─────────────────────────

func TestListAudit_NoTenant_Returns404(t *testing.T) {
	t.Parallel()
	ctrl := NewAuditController(&stubAuditService{})
	req := httptest.NewRequest(http.MethodGet, "/v2/admin/tenants/x/audit-logs", nil)
	// no tenant in context
	w := httptest.NewRecorder()
	ctrl.List(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestListAudit_NoClaims_Returns403(t *testing.T) {
	t.Parallel()
	ctrl := NewAuditController(&stubAuditService{})
	req := httptest.NewRequest(http.MethodGet, "/v2/admin/tenants/x/audit-logs", nil)
	req = req.WithContext(mw.WithTenant(context.Background(), &fakeAuditTDA{slug: "acme", id: "t1"}))
	w := httptest.NewRecorder()
	ctrl.List(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestListAudit_ViewerClaims_Returns403(t *testing.T) {
	t.Parallel()
	ctrl := NewAuditController(&stubAuditService{})
	req := httptest.NewRequest(http.MethodGet, "/v2/admin/tenants/x/audit-logs", nil)
	ctx := ctxWith(&fakeAuditTDA{slug: "acme", id: "t1"}, &jwtx.AdminAccessClaims{AdminType: "viewer", Perms: nil})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	ctrl.List(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestListAudit_InvalidLimit_Returns400(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		limit string
	}{
		{"non-numeric", "abc"},
		{"zero", "0"},
		{"negative", "-5"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctrl := NewAuditController(&stubAuditService{})
			req := httptest.NewRequest(http.MethodGet, "/v2/admin/tenants/x/audit-logs?limit="+tc.limit, nil)
			ctx := ctxWith(&fakeAuditTDA{slug: "acme", id: "t1"}, readClaims())
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			ctrl.List(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("limit=%s: expected 400, got %d", tc.limit, w.Code)
			}
		})
	}
}

func TestListAudit_InvalidOffset_Returns400(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		offset string
	}{
		{"non-numeric", "xyz"},
		{"negative", "-1"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctrl := NewAuditController(&stubAuditService{})
			req := httptest.NewRequest(http.MethodGet, "/v2/admin/tenants/x/audit-logs?offset="+tc.offset, nil)
			ctx := ctxWith(&fakeAuditTDA{slug: "acme", id: "t1"}, readClaims())
			req = req.WithContext(ctx)
			w := httptest.NewRecorder()
			ctrl.List(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("offset=%s: expected 400, got %d", tc.offset, w.Code)
			}
		})
	}
}

func TestListAudit_InvalidFrom_Returns400(t *testing.T) {
	t.Parallel()
	ctrl := NewAuditController(&stubAuditService{})
	req := httptest.NewRequest(http.MethodGet, "/v2/admin/tenants/x/audit-logs?from=not-a-date", nil)
	ctx := ctxWith(&fakeAuditTDA{slug: "acme", id: "t1"}, readClaims())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	ctrl.List(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestListAudit_InvalidTo_Returns400(t *testing.T) {
	t.Parallel()
	ctrl := NewAuditController(&stubAuditService{})
	req := httptest.NewRequest(http.MethodGet, "/v2/admin/tenants/x/audit-logs?to=2026-13-01", nil)
	ctx := ctxWith(&fakeAuditTDA{slug: "acme", id: "t1"}, readClaims())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	ctrl.List(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestListAudit_DefaultLimit_Is50(t *testing.T) {
	t.Parallel()

	var capturedFilter repository.AuditFilter
	svc := &capturingAuditService{capturedFilter: &capturedFilter}
	ctrl := NewAuditController(svc)

	req := httptest.NewRequest(http.MethodGet, "/v2/admin/tenants/x/audit-logs", nil)
	ctx := ctxWith(&fakeAuditTDA{slug: "acme", id: "t1"}, readClaims())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	ctrl.List(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if capturedFilter.Limit != 50 {
		t.Fatalf("expected default limit=50, got %d", capturedFilter.Limit)
	}
}

func TestListAudit_LimitOver100_ClampsTo100(t *testing.T) {
	t.Parallel()

	var capturedFilter repository.AuditFilter
	svc := &capturingAuditService{capturedFilter: &capturedFilter}
	ctrl := NewAuditController(svc)

	req := httptest.NewRequest(http.MethodGet, "/v2/admin/tenants/x/audit-logs?limit=200", nil)
	ctx := ctxWith(&fakeAuditTDA{slug: "acme", id: "t1"}, readClaims())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	ctrl.List(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if capturedFilter.Limit != 100 {
		t.Fatalf("expected clamped limit=100, got %d", capturedFilter.Limit)
	}
}

func TestListAudit_ValidLimit_IsRespected(t *testing.T) {
	t.Parallel()

	var capturedFilter repository.AuditFilter
	svc := &capturingAuditService{capturedFilter: &capturedFilter}
	ctrl := NewAuditController(svc)

	req := httptest.NewRequest(http.MethodGet, "/v2/admin/tenants/x/audit-logs?limit=25", nil)
	ctx := ctxWith(&fakeAuditTDA{slug: "acme", id: "t1"}, readClaims())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	ctrl.List(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if capturedFilter.Limit != 25 {
		t.Fatalf("expected limit=25, got %d", capturedFilter.Limit)
	}
}

func TestListAudit_Success_ReturnsJSON(t *testing.T) {
	t.Parallel()

	svc := &stubAuditService{
		events: []audit.AuditEvent{{ID: "evt-1", Type: audit.EventLogin}},
		total:  1,
	}
	ctrl := NewAuditController(svc)

	req := httptest.NewRequest(http.MethodGet, "/v2/admin/tenants/x/audit-logs", nil)
	ctx := ctxWith(&fakeAuditTDA{slug: "acme", id: "t1"}, tenantReadClaims())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	ctrl.List(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if body["total"].(float64) != 1 {
		t.Fatalf("expected total=1, got %v", body["total"])
	}
}

// ───────────────────────── Get handler tests ─────────────────────────

func TestGetAudit_NoTenant_Returns404(t *testing.T) {
	t.Parallel()
	ctrl := NewAuditController(&stubAuditService{})
	req := httptest.NewRequest(http.MethodGet, "/v2/admin/tenants/x/audit-logs/abc", nil)
	w := httptest.NewRecorder()
	ctrl.Get(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetAudit_NoClaims_Returns403(t *testing.T) {
	t.Parallel()
	ctrl := NewAuditController(&stubAuditService{})
	req := httptest.NewRequest(http.MethodGet, "/v2/admin/tenants/x/audit-logs/abc", nil)
	ctx := mw.WithTenant(context.Background(), &fakeAuditTDA{slug: "acme", id: "t1"})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	ctrl.Get(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestGetAudit_NotFound_Returns404(t *testing.T) {
	t.Parallel()
	ctrl := NewAuditController(&stubAuditService{single: nil})
	req := httptest.NewRequest(http.MethodGet, "/v2/admin/tenants/x/audit-logs/missing", nil)
	req.SetPathValue("auditId", "missing")
	ctx := ctxWith(&fakeAuditTDA{slug: "acme", id: "t1"}, readClaims())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	ctrl.Get(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestGetAudit_Found_Returns200(t *testing.T) {
	t.Parallel()
	evt := &audit.AuditEvent{ID: "evt-1", Type: audit.EventLogin, TenantID: "t1"}
	ctrl := NewAuditController(&stubAuditService{single: evt})
	req := httptest.NewRequest(http.MethodGet, "/v2/admin/tenants/x/audit-logs/evt-1", nil)
	req.SetPathValue("auditId", "evt-1")
	ctx := ctxWith(&fakeAuditTDA{slug: "acme", id: "t1"}, readClaims())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	ctrl.Get(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// ───────────────────────── Purge handler tests ─────────────────────────

func TestPurgeAudit_TenantAdmin_Returns403(t *testing.T) {
	t.Parallel()
	ctrl := NewAuditController(&stubAuditService{})
	body := strings.NewReader(`{"days":30}`)
	req := httptest.NewRequest(http.MethodPost, "/v2/admin/tenants/x/audit-logs/purge", body)
	ctx := ctxWith(&fakeAuditTDA{slug: "acme", id: "t1"}, tenantReadClaims())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	ctrl.Purge(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestPurgeAudit_InvalidJSON_Returns400(t *testing.T) {
	t.Parallel()
	ctrl := NewAuditController(&stubAuditService{})
	body := strings.NewReader(`not json`)
	req := httptest.NewRequest(http.MethodPost, "/v2/admin/tenants/x/audit-logs/purge", body)
	ctx := ctxWith(&fakeAuditTDA{slug: "acme", id: "t1"}, purgeClaims())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	ctrl.Purge(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestPurgeAudit_NeitherBeforeNorDays_Returns400(t *testing.T) {
	t.Parallel()
	ctrl := NewAuditController(&stubAuditService{})
	body := strings.NewReader(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/v2/admin/tenants/x/audit-logs/purge", body)
	ctx := ctxWith(&fakeAuditTDA{slug: "acme", id: "t1"}, purgeClaims())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	ctrl.Purge(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestPurgeAudit_InvalidBeforeFormat_Returns400(t *testing.T) {
	t.Parallel()
	ctrl := NewAuditController(&stubAuditService{})
	body := strings.NewReader(`{"before":"2026-01-01"}`)
	req := httptest.NewRequest(http.MethodPost, "/v2/admin/tenants/x/audit-logs/purge", body)
	ctx := ctxWith(&fakeAuditTDA{slug: "acme", id: "t1"}, purgeClaims())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	ctrl.Purge(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestPurgeAudit_Success_Returns200(t *testing.T) {
	t.Parallel()
	ctrl := NewAuditController(&stubAuditService{deleted: 42})
	body := strings.NewReader(`{"days":30}`)
	req := httptest.NewRequest(http.MethodPost, "/v2/admin/tenants/x/audit-logs/purge", body)
	ctx := ctxWith(&fakeAuditTDA{slug: "acme", id: "t1"}, purgeClaims())
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	ctrl.Purge(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if result["deleted"].(float64) != 42 {
		t.Fatalf("expected deleted=42, got %v", result["deleted"])
	}
}

// ───────────────────────── Capturing service stub ─────────────────────────

// capturingAuditService captures the filter passed to List, for limit/offset assertions.
type capturingAuditService struct {
	capturedFilter *repository.AuditFilter
}

func (s *capturingAuditService) List(_ context.Context, _ string, f repository.AuditFilter) ([]audit.AuditEvent, int64, error) {
	*s.capturedFilter = f
	return nil, 0, nil
}
func (s *capturingAuditService) GetByID(_ context.Context, _ string, _ string) (*audit.AuditEvent, error) {
	return nil, nil
}
func (s *capturingAuditService) Purge(_ context.Context, _ string, _ time.Time) (int64, error) {
	return 0, nil
}
