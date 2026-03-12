package router

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	storev2 "github.com/dropDatabas3/hellojohn/internal/store"
)

func TestTenantMailingRateLimit(t *testing.T) {
	limiter := mw.NewMemoryRateLimiter(5, time.Minute)
	defer limiter.Stop()

	handler := mw.Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), mw.WithRateLimit(mw.RateLimitConfig{
		Limiter: limiter,
		KeyFunc: tenantMailingRateKey,
	}))

	mux := http.NewServeMux()
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/mailing/test", handler)

	for i := 1; i <= 6; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v2/admin/tenants/acme/mailing/test", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		expected := http.StatusOK
		if i == 6 {
			expected = http.StatusTooManyRequests
		}
		if rec.Code != expected {
			t.Fatalf("attempt %d: expected %d, got %d", i, expected, rec.Code)
		}
	}

	// Different tenant key should start a new bucket.
	req := httptest.NewRequest(http.MethodPost, "/v2/admin/tenants/other/mailing/test", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected other tenant to pass, got %d", rec.Code)
	}
}

func TestTenantMailingRateLimitUsesCanonicalTenantFromContext(t *testing.T) {
	limiter := mw.NewMemoryRateLimiter(1, time.Minute)
	defer limiter.Stop()

	tenantCtx := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := mw.WithTenant(r.Context(), &fakeTenantDataAccess{
				slug: "acme",
				id:   "tenant-123",
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	handler := mw.Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), tenantCtx, mw.WithRateLimit(mw.RateLimitConfig{
		Limiter: limiter,
		KeyFunc: tenantMailingRateKey,
	}))

	mux := http.NewServeMux()
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/mailing/test", handler)

	req := httptest.NewRequest(http.MethodPost, "/v2/admin/tenants/acme/mailing/test", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first request expected %d, got %d", http.StatusOK, rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/v2/admin/tenants/550e8400-e29b-41d4-a716-446655440000/mailing/test", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request expected %d, got %d", http.StatusTooManyRequests, rec.Code)
	}
}

type fakeTenantDataAccess struct {
	storev2.TenantDataAccess
	slug string
	id   string
}

func (f *fakeTenantDataAccess) Slug() string { return f.slug }
func (f *fakeTenantDataAccess) ID() string   { return f.id }
