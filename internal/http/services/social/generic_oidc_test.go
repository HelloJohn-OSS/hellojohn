package social

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

type genericOIDCTenantProviderStub struct {
	tenant *repository.Tenant
}

func (s genericOIDCTenantProviderStub) GetTenant(context.Context, string) (*repository.Tenant, error) {
	if s.tenant == nil {
		return nil, errors.New("tenant not found")
	}
	return s.tenant, nil
}

func (s genericOIDCTenantProviderStub) GetClient(context.Context, string, string) (*repository.Client, error) {
	return nil, errors.New("not implemented")
}

func TestGenericOIDCFactory_BuildForAlias_DiscoverySuccess(t *testing.T) {
	var discovery *httptest.Server
	discovery = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authorization_endpoint": discovery.URL + "/authorize",
			"token_endpoint":         discovery.URL + "/token",
			"userinfo_endpoint":      discovery.URL + "/userinfo",
			"issuer":                 discovery.URL,
		})
	}))
	defer discovery.Close()

	factory := &GenericOIDCFactory{
		TenantProvider: genericOIDCTenantProviderStub{
			tenant: tenantWithCustomOIDCAlias("corp-sso", discovery.URL+"/.well-known/openid-configuration"),
		},
	}

	client, err := factory.BuildForAlias(context.Background(), "tenant-a", "https://auth.example.com", "corp-sso")
	if err != nil {
		t.Fatalf("BuildForAlias returned error: %v", err)
	}

	authURL, err := client.AuthURL(context.Background(), "state-1", "nonce-1")
	if err != nil {
		t.Fatalf("AuthURL returned error: %v", err)
	}
	if !strings.HasPrefix(authURL, discovery.URL+"/authorize?") {
		t.Fatalf("unexpected authURL: %s", authURL)
	}
	if !strings.Contains(authURL, "redirect_uri=https%3A%2F%2Fauth.example.com%2Fv2%2Fauth%2Fsocial%2Fcorp-sso%2Fcallback") {
		t.Fatalf("expected alias callback redirect_uri in auth URL, got: %s", authURL)
	}
}

func TestGenericOIDCFactory_BuildForAlias_DiscoveryFail(t *testing.T) {
	discovery := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer discovery.Close()

	factory := &GenericOIDCFactory{
		TenantProvider: genericOIDCTenantProviderStub{
			tenant: tenantWithCustomOIDCAlias("corp-sso", discovery.URL+"/.well-known/openid-configuration"),
		},
	}

	if _, err := factory.BuildForAlias(context.Background(), "tenant-a", "https://auth.example.com", "corp-sso"); err == nil {
		t.Fatalf("expected discovery failure for invalid well-known endpoint")
	}
}

func TestGitLabFactory_Build_UsesGitLabAlias(t *testing.T) {
	var discovery *httptest.Server
	discovery = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"authorization_endpoint": discovery.URL + "/authorize",
			"token_endpoint":         discovery.URL + "/token",
			"userinfo_endpoint":      discovery.URL + "/userinfo",
			"issuer":                 discovery.URL,
		})
	}))
	defer discovery.Close()

	gitLabFactory := &GitLabFactory{
		TenantProvider: genericOIDCTenantProviderStub{
			tenant: tenantWithCustomOIDCAlias("gitlab", discovery.URL+"/.well-known/openid-configuration"),
		},
	}

	client, err := gitLabFactory.Build(context.Background(), "tenant-a", "https://auth.example.com")
	if err != nil {
		t.Fatalf("gitlab build failed: %v", err)
	}
	authURL, err := client.AuthURL(context.Background(), "state-1", "nonce-1")
	if err != nil {
		t.Fatalf("gitlab authURL failed: %v", err)
	}
	if !strings.HasPrefix(authURL, discovery.URL+"/authorize?") {
		t.Fatalf("unexpected gitlab auth URL: %s", authURL)
	}
}

func tenantWithCustomOIDCAlias(alias, wellKnownURL string) *repository.Tenant {
	return &repository.Tenant{
		Slug: "tenant-a",
		Settings: repository.TenantSettings{
			SocialProviders: &repository.SocialConfig{
				CustomOIDCProviders: []repository.CustomOIDCConfig{
					{
						Alias:           alias,
						WellKnownURL:    wellKnownURL,
						ClientID:        "client-id",
						ClientSecretEnc: "client-secret-plain",
						Enabled:         true,
					},
				},
			},
		},
	}
}
