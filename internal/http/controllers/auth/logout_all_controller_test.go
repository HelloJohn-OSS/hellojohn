package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	cache "github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	sessiondto "github.com/dropDatabas3/hellojohn/internal/http/dto/session"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

type fakeLogoutService struct {
	lastReq    dto.LogoutRequest
	lastTenant string
	result     *dto.LogoutResult
	err        error
}

func (f *fakeLogoutService) Logout(_ context.Context, in dto.LogoutRequest, tenantSlug string) (*dto.LogoutResult, error) {
	f.lastReq = in
	f.lastTenant = tenantSlug
	if f.result == nil {
		return &dto.LogoutResult{}, f.err
	}
	return f.result, f.err
}

func (f *fakeLogoutService) LogoutAll(context.Context, dto.LogoutAllRequest, string) error {
	return nil
}

type fakeDAL struct {
	tenants map[string]store.TenantDataAccess
}

func (d *fakeDAL) ForTenant(_ context.Context, slugOrID string) (store.TenantDataAccess, error) {
	if tda, ok := d.tenants[slugOrID]; ok {
		return tda, nil
	}
	return nil, repository.ErrNotFound
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
	slug     string
	id       string
	settings *repository.TenantSettings
}

func (t *fakeTDA) Slug() string { return t.slug }
func (t *fakeTDA) ID() string   { return t.id }
func (t *fakeTDA) Settings() *repository.TenantSettings {
	if t.settings == nil {
		return &repository.TenantSettings{}
	}
	return t.settings
}
func (t *fakeTDA) Driver() string                               { return "test" }
func (t *fakeTDA) Users() repository.UserRepository             { return nil }
func (t *fakeTDA) Tokens() repository.TokenRepository           { return nil }
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

type fakeSessionCache struct {
	data map[string]string
}

func (c *fakeSessionCache) Get(_ context.Context, key string) (string, error) {
	if v, ok := c.data[key]; ok {
		return v, nil
	}
	return "", cache.ErrNotFound
}
func (c *fakeSessionCache) Set(_ context.Context, key, value string, _ time.Duration) error {
	if c.data == nil {
		c.data = make(map[string]string)
	}
	c.data[key] = value
	return nil
}
func (c *fakeSessionCache) Delete(_ context.Context, key string) error {
	delete(c.data, key)
	return nil
}
func (c *fakeSessionCache) GetDel(_ context.Context, key string) (string, error) {
	if v, ok := c.data[key]; ok {
		delete(c.data, key)
		return v, nil
	}
	return "", cache.ErrNotFound
}
func (c *fakeSessionCache) Exists(_ context.Context, key string) (bool, error) {
	_, ok := c.data[key]
	return ok, nil
}
func (c *fakeSessionCache) Ping(context.Context) error                 { return nil }
func (c *fakeSessionCache) Close() error                               { return nil }
func (c *fakeSessionCache) Stats(context.Context) (cache.Stats, error) { return cache.Stats{}, nil }

func TestLogoutControllerTenantCookiePolicy(t *testing.T) {
	secureFalse := false
	secureTrue := true

	baseConfig := sessiondto.SessionLogoutConfig{
		CookieName:   "sid",
		CookieDomain: "global.example.com",
		SameSite:     "Lax",
		Secure:       true,
	}

	t.Run("uses tenant policy from request tenant", func(t *testing.T) {
		svc := &fakeLogoutService{}
		dal := &fakeDAL{
			tenants: map[string]store.TenantDataAccess{
				"tenant-a": &fakeTDA{
					slug: "tenant-a",
					id:   "tenant-a",
					settings: &repository.TenantSettings{
						CookiePolicy: &repository.CookiePolicy{
							Domain:   "tenant-a.example.com",
							SameSite: "none",
							Secure:   &secureFalse,
						},
					},
				},
			},
		}

		controller := NewLogoutController(svc, baseConfig, dal, nil)
		req := httptest.NewRequest(http.MethodPost, "/v2/auth/logout", strings.NewReader(`{"tenant_id":"tenant-a"}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "sid", Value: "session-a"})
		rec := httptest.NewRecorder()

		controller.Logout(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", rec.Code)
		}
		if svc.lastTenant != "tenant-a" {
			t.Fatalf("expected service tenant tenant-a, got %q", svc.lastTenant)
		}

		setCookie := rec.Result().Header.Get("Set-Cookie")
		if !strings.Contains(setCookie, "Domain=tenant-a.example.com") {
			t.Fatalf("expected tenant domain in deletion cookie, got %q", setCookie)
		}
		if !strings.Contains(setCookie, "SameSite=None") {
			t.Fatalf("expected tenant sameSite None in deletion cookie, got %q", setCookie)
		}
		if strings.Contains(setCookie, "Secure") {
			t.Fatalf("expected non-secure deletion cookie from tenant policy, got %q", setCookie)
		}
	})

	t.Run("session tenant wins on conflict for cookie policy", func(t *testing.T) {
		svc := &fakeLogoutService{}
		dal := &fakeDAL{
			tenants: map[string]store.TenantDataAccess{
				"tenant-a": &fakeTDA{
					slug: "tenant-a",
					id:   "tenant-a",
					settings: &repository.TenantSettings{
						CookiePolicy: &repository.CookiePolicy{
							Domain:   "tenant-a.example.com",
							SameSite: "strict",
							Secure:   &secureTrue,
						},
					},
				},
				"tenant-b": &fakeTDA{
					slug: "tenant-b",
					id:   "tenant-b",
					settings: &repository.TenantSettings{
						CookiePolicy: &repository.CookiePolicy{
							Domain:   "tenant-b.example.com",
							SameSite: "none",
							Secure:   &secureFalse,
						},
					},
				},
			},
		}

		sessionID := "session-conflict"
		payload, _ := json.Marshal(sessiondto.SessionPayload{
			UserID:   "user-1",
			TenantID: "tenant-b",
			Expires:  time.Now().Add(1 * time.Hour),
		})
		cacheData := map[string]string{
			"sid:" + tokens.SHA256Base64URL(sessionID): string(payload),
		}
		controller := NewLogoutController(svc, baseConfig, dal, &fakeSessionCache{data: cacheData})

		req := httptest.NewRequest(http.MethodPost, "/v2/auth/logout", strings.NewReader(`{"tenant_id":"tenant-a"}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "sid", Value: sessionID})
		rec := httptest.NewRecorder()

		controller.Logout(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", rec.Code)
		}

		setCookie := rec.Result().Header.Get("Set-Cookie")
		if !strings.Contains(setCookie, "Domain=tenant-b.example.com") {
			t.Fatalf("expected session-tenant domain in deletion cookie, got %q", setCookie)
		}
		if !strings.Contains(setCookie, "SameSite=None") {
			t.Fatalf("expected session-tenant sameSite None in deletion cookie, got %q", setCookie)
		}
		if strings.Contains(setCookie, "Secure") {
			t.Fatalf("expected non-secure deletion cookie from session tenant policy, got %q", setCookie)
		}
	})

	t.Run("falls back to global cookie policy when tenant is unresolved", func(t *testing.T) {
		svc := &fakeLogoutService{}
		controller := NewLogoutController(svc, baseConfig, &fakeDAL{tenants: map[string]store.TenantDataAccess{}}, nil)

		req := httptest.NewRequest(http.MethodPost, "/v2/auth/logout", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "sid", Value: "session-global"})
		rec := httptest.NewRecorder()

		controller.Logout(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", rec.Code)
		}

		setCookie := rec.Result().Header.Get("Set-Cookie")
		if !strings.Contains(setCookie, "Domain=global.example.com") {
			t.Fatalf("expected global domain in deletion cookie, got %q", setCookie)
		}
		if !strings.Contains(setCookie, "SameSite=Lax") {
			t.Fatalf("expected global sameSite Lax in deletion cookie, got %q", setCookie)
		}
		if !strings.Contains(setCookie, "Secure") {
			t.Fatalf("expected secure deletion cookie from global config, got %q", setCookie)
		}
	})
}
