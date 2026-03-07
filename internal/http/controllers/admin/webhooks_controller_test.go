package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

type fakeWebhookRepo struct {
	listResp    []*repository.WebhookDelivery
	listErr     error
	called      bool
	lastWebhook string
	lastLimit   int
	lastOffset  int
	lastFilter  repository.WebhookDeliveryFilter
}

func (f *fakeWebhookRepo) InsertDelivery(_ context.Context, _ *repository.WebhookDelivery) error {
	return nil
}

func (f *fakeWebhookRepo) FetchPending(_ context.Context, _ int) ([]*repository.WebhookDelivery, error) {
	return nil, nil
}

func (f *fakeWebhookRepo) UpdateDeliveryStatus(_ context.Context, _ string, _ string, _ int, _ *time.Time, _ *time.Time, _ *int, _ *string) error {
	return nil
}

func (f *fakeWebhookRepo) ListDeliveries(_ context.Context, webhookID string, limit, offset int, filter repository.WebhookDeliveryFilter) ([]*repository.WebhookDelivery, error) {
	f.called = true
	f.lastWebhook = webhookID
	f.lastLimit = limit
	f.lastOffset = offset
	f.lastFilter = filter
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listResp, nil
}

type fakeWebhookTDA struct {
	slug         string
	id           string
	requireDBErr error
	repo         repository.WebhookRepository
}

func (f *fakeWebhookTDA) Slug() string                                 { return f.slug }
func (f *fakeWebhookTDA) ID() string                                   { return f.id }
func (f *fakeWebhookTDA) Settings() *repository.TenantSettings         { return &repository.TenantSettings{} }
func (f *fakeWebhookTDA) Driver() string                               { return "test" }
func (f *fakeWebhookTDA) Users() repository.UserRepository             { return nil }
func (f *fakeWebhookTDA) Tokens() repository.TokenRepository           { return nil }
func (f *fakeWebhookTDA) MFA() repository.MFARepository                { return nil }
func (f *fakeWebhookTDA) Consents() repository.ConsentRepository       { return nil }
func (f *fakeWebhookTDA) RBAC() repository.RBACRepository              { return nil }
func (f *fakeWebhookTDA) Schema() repository.SchemaRepository          { return nil }
func (f *fakeWebhookTDA) EmailTokens() repository.EmailTokenRepository { return nil }
func (f *fakeWebhookTDA) Identities() repository.IdentityRepository    { return nil }
func (f *fakeWebhookTDA) Sessions() repository.SessionRepository       { return nil }
func (f *fakeWebhookTDA) Audit() repository.AuditRepository            { return nil }
func (f *fakeWebhookTDA) Claims() repository.ClaimRepository           { return nil }
func (f *fakeWebhookTDA) Webhooks() repository.WebhookRepository       { return f.repo }
func (f *fakeWebhookTDA) Clients() repository.ClientRepository         { return nil }
func (f *fakeWebhookTDA) Scopes() repository.ScopeRepository           { return nil }
func (f *fakeWebhookTDA) Cache() cache.Client                          { return nil }
func (f *fakeWebhookTDA) CacheRepo() repository.CacheRepository        { return nil }
func (f *fakeWebhookTDA) Mailer() store.MailSender                     { return nil }
func (f *fakeWebhookTDA) Invitations() repository.InvitationRepository { return nil }
func (f *fakeWebhookTDA) WebAuthn() repository.WebAuthnRepository      { return nil }
func (f *fakeWebhookTDA) HasDB() bool                                  { return f.requireDBErr == nil }
func (f *fakeWebhookTDA) RequireDB() error                             { return f.requireDBErr }
func (f *fakeWebhookTDA) InfraStats(_ context.Context) (*store.TenantInfraStats, error) {
	return nil, nil
}

type deliveriesResponseBody struct {
	Deliveries []map[string]any `json:"deliveries"`
	Limit      int              `json:"limit"`
	Offset     int              `json:"offset"`
	HasMore    bool             `json:"has_more"`
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail"`
}

func newListDeliveriesRequest(rawQuery string, tda store.TenantDataAccess) *http.Request {
	url := "/v2/admin/tenants/t1/webhooks/wh_test_123/deliveries"
	if rawQuery != "" {
		url += "?" + rawQuery
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	if tda != nil {
		req = req.WithContext(mw.WithTenant(req.Context(), tda))
	}
	return req
}

func decodeResponse[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var out T
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	return out
}

func makeDeliveries(count int) []*repository.WebhookDelivery {
	items := make([]*repository.WebhookDelivery, 0, count)
	now := time.Now().UTC()
	for i := 0; i < count; i++ {
		items = append(items, &repository.WebhookDelivery{
			ID:        "d-" + strconvItoa(i),
			WebhookID: "wh_test_123",
			EventType: "user.login",
			Status:    "delivered",
			Attempts:  1,
			CreatedAt: now,
		})
	}
	return items
}

func strconvItoa(i int) string {
	return strconv.FormatInt(int64(i), 10)
}

func TestListDeliveries_TC01_ValidParamsFull(t *testing.T) {
	t.Parallel()

	repo := &fakeWebhookRepo{listResp: []*repository.WebhookDelivery{}}
	ctrl := NewWebhooksController(nil)
	tda := &fakeWebhookTDA{slug: "acme", id: "t1", repo: repo}

	fromRaw := "2026-01-01T00:00:00Z"
	toRaw := "2026-01-31T23:59:59Z"
	req := newListDeliveriesRequest("limit=10&offset=0&from="+fromRaw+"&to="+toRaw+"&result=delivered&event=user.login", tda)
	rec := httptest.NewRecorder()

	ctrl.ListDeliveries(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !repo.called {
		t.Fatal("expected repository ListDeliveries to be called")
	}
	if repo.lastWebhook != "wh_test_123" {
		t.Fatalf("expected webhook id wh_test_123, got %s", repo.lastWebhook)
	}
	if repo.lastLimit != 10 {
		t.Fatalf("expected limit=10, got %d", repo.lastLimit)
	}
	if repo.lastOffset != 0 {
		t.Fatalf("expected offset=0, got %d", repo.lastOffset)
	}

	wantFrom, _ := time.Parse(time.RFC3339, fromRaw)
	wantTo, _ := time.Parse(time.RFC3339, toRaw)
	if !repo.lastFilter.From.Equal(wantFrom) {
		t.Fatalf("expected filter.From=%s, got %s", wantFrom, repo.lastFilter.From)
	}
	if !repo.lastFilter.To.Equal(wantTo) {
		t.Fatalf("expected filter.To=%s, got %s", wantTo, repo.lastFilter.To)
	}
	if repo.lastFilter.Result != "delivered" {
		t.Fatalf("expected result=delivered, got %q", repo.lastFilter.Result)
	}
	if repo.lastFilter.Event != "user.login" {
		t.Fatalf("expected event=user.login, got %q", repo.lastFilter.Event)
	}
}

func TestListDeliveries_TC02_FromAfterTo_Returns400(t *testing.T) {
	t.Parallel()

	repo := &fakeWebhookRepo{}
	ctrl := NewWebhooksController(nil)
	tda := &fakeWebhookTDA{slug: "acme", id: "t1", repo: repo}
	req := newListDeliveriesRequest("from=2026-02-01T00:00:00Z&to=2026-01-01T00:00:00Z", tda)
	rec := httptest.NewRecorder()

	ctrl.ListDeliveries(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if repo.called {
		t.Fatal("repository must not be called for invalid params")
	}
	errResp := decodeResponse[errorBody](t, rec)
	if !strings.Contains(errResp.Detail, "from must be before or equal to to") {
		t.Fatalf("unexpected error detail: %q", errResp.Detail)
	}
}

func TestListDeliveries_TC03_RangeGreaterThan90Days_Returns400(t *testing.T) {
	t.Parallel()

	repo := &fakeWebhookRepo{}
	ctrl := NewWebhooksController(nil)
	tda := &fakeWebhookTDA{slug: "acme", id: "t1", repo: repo}
	req := newListDeliveriesRequest("from=2025-01-01T00:00:00Z&to=2026-01-01T00:00:00Z", tda)
	rec := httptest.NewRecorder()

	ctrl.ListDeliveries(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if repo.called {
		t.Fatal("repository must not be called for invalid params")
	}
	errResp := decodeResponse[errorBody](t, rec)
	if !strings.Contains(errResp.Detail, "date range cannot exceed 90 days") {
		t.Fatalf("unexpected error detail: %q", errResp.Detail)
	}
}

func TestListDeliveries_TC04_InvalidResult_Returns400(t *testing.T) {
	t.Parallel()

	repo := &fakeWebhookRepo{}
	ctrl := NewWebhooksController(nil)
	tda := &fakeWebhookTDA{slug: "acme", id: "t1", repo: repo}
	req := newListDeliveriesRequest("result=broken", tda)
	rec := httptest.NewRecorder()

	ctrl.ListDeliveries(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if repo.called {
		t.Fatal("repository must not be called for invalid params")
	}
}

func TestListDeliveries_TC05_InvalidDateFormat_Returns400(t *testing.T) {
	t.Parallel()

	repo := &fakeWebhookRepo{}
	ctrl := NewWebhooksController(nil)
	tda := &fakeWebhookTDA{slug: "acme", id: "t1", repo: repo}
	req := newListDeliveriesRequest("from=2026-01-01", tda)
	rec := httptest.NewRecorder()

	ctrl.ListDeliveries(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if repo.called {
		t.Fatal("repository must not be called for invalid params")
	}
}

func TestListDeliveries_TC06_EventOver100Chars_Returns400(t *testing.T) {
	t.Parallel()

	repo := &fakeWebhookRepo{}
	ctrl := NewWebhooksController(nil)
	tda := &fakeWebhookTDA{slug: "acme", id: "t1", repo: repo}
	tooLong := strings.Repeat("a", 101)
	req := newListDeliveriesRequest("event="+tooLong, tda)
	rec := httptest.NewRecorder()

	ctrl.ListDeliveries(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if repo.called {
		t.Fatal("repository must not be called for invalid params")
	}
}

func TestListDeliveries_TC07_NoFilters_BackwardCompatible(t *testing.T) {
	t.Parallel()

	repo := &fakeWebhookRepo{listResp: []*repository.WebhookDelivery{}}
	ctrl := NewWebhooksController(nil)
	tda := &fakeWebhookTDA{slug: "acme", id: "t1", repo: repo}
	req := newListDeliveriesRequest("limit=25&offset=0", tda)
	rec := httptest.NewRecorder()

	ctrl.ListDeliveries(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !repo.called {
		t.Fatal("expected repository ListDeliveries to be called")
	}
	if !repo.lastFilter.From.IsZero() {
		t.Fatalf("expected zero From filter, got %s", repo.lastFilter.From)
	}
	if !repo.lastFilter.To.IsZero() {
		t.Fatalf("expected zero To filter, got %s", repo.lastFilter.To)
	}
	if repo.lastFilter.Result != "" {
		t.Fatalf("expected empty Result filter, got %q", repo.lastFilter.Result)
	}
	if repo.lastFilter.Event != "" {
		t.Fatalf("expected empty Event filter, got %q", repo.lastFilter.Event)
	}
}

func TestListDeliveries_TC08_HasMoreTrueWhenLimitPlusOne(t *testing.T) {
	t.Parallel()

	repo := &fakeWebhookRepo{listResp: makeDeliveries(26)}
	ctrl := NewWebhooksController(nil)
	tda := &fakeWebhookTDA{slug: "acme", id: "t1", repo: repo}
	req := newListDeliveriesRequest("limit=25&offset=0", tda)
	rec := httptest.NewRecorder()

	ctrl.ListDeliveries(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	resp := decodeResponse[deliveriesResponseBody](t, rec)
	if len(resp.Deliveries) != 25 {
		t.Fatalf("expected 25 deliveries, got %d", len(resp.Deliveries))
	}
	if !resp.HasMore {
		t.Fatal("expected has_more=true")
	}
}

func TestListDeliveries_TC09_HasMoreFalseWhenExactlyLimit(t *testing.T) {
	t.Parallel()

	repo := &fakeWebhookRepo{listResp: makeDeliveries(25)}
	ctrl := NewWebhooksController(nil)
	tda := &fakeWebhookTDA{slug: "acme", id: "t1", repo: repo}
	req := newListDeliveriesRequest("limit=25&offset=0", tda)
	rec := httptest.NewRecorder()

	ctrl.ListDeliveries(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	resp := decodeResponse[deliveriesResponseBody](t, rec)
	if len(resp.Deliveries) != 25 {
		t.Fatalf("expected 25 deliveries, got %d", len(resp.Deliveries))
	}
	if resp.HasMore {
		t.Fatal("expected has_more=false")
	}
}
