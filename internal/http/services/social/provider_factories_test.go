package social

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	cache "github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

func tenantWithStandardSocialProviders() *repository.Tenant {
	return &repository.Tenant{
		Slug: "tenant-a",
		Settings: repository.TenantSettings{
			SocialLoginEnabled: true,
			SocialProviders: &repository.SocialConfig{
				GoogleEnabled:      true,
				GoogleClient:       "google-client",
				GoogleSecretEnc:    "google-secret-plain",
				GitHubEnabled:      true,
				GitHubClient:       "github-client",
				GitHubSecretEnc:    "github-secret-plain",
				FacebookEnabled:    true,
				FacebookClient:     "facebook-client",
				FacebookSecretEnc:  "facebook-secret-plain",
				DiscordEnabled:     true,
				DiscordClient:      "discord-client",
				DiscordSecretEnc:   "discord-secret-plain",
				MicrosoftEnabled:   true,
				MicrosoftClient:    "microsoft-client",
				MicrosoftSecretEnc: "microsoft-secret-plain",
				MicrosoftTenant:    "common",
				LinkedInEnabled:    true,
				LinkedInClient:     "linkedin-client",
				LinkedInSecretEnc:  "linkedin-secret-plain",
			},
		},
	}
}

func TestStandardProviderFactories_BuildAndAuthURL(t *testing.T) {
	tenantProvider := genericOIDCTenantProviderStub{
		tenant: tenantWithStandardSocialProviders(),
	}
	baseURL := "https://auth.example.com"

	cases := []struct {
		name                string
		expectedRedirectURI string
		build               func() (OIDCClient, error)
	}{
		{
			name:                "google",
			expectedRedirectURI: baseURL + "/v2/auth/social/google/callback",
			build: func() (OIDCClient, error) {
				return (&GoogleFactory{TenantProvider: tenantProvider}).Build(context.Background(), "tenant-a", baseURL)
			},
		},
		{
			name:                "github",
			expectedRedirectURI: baseURL + "/v2/auth/social/github/callback",
			build: func() (OIDCClient, error) {
				return (&GitHubFactory{TenantProvider: tenantProvider}).Build(context.Background(), "tenant-a", baseURL)
			},
		},
		{
			name:                "facebook",
			expectedRedirectURI: baseURL + "/v2/auth/social/facebook/callback",
			build: func() (OIDCClient, error) {
				return (&FacebookFactory{TenantProvider: tenantProvider}).Build(context.Background(), "tenant-a", baseURL)
			},
		},
		{
			name:                "discord",
			expectedRedirectURI: baseURL + "/v2/auth/social/discord/callback",
			build: func() (OIDCClient, error) {
				return (&DiscordFactory{TenantProvider: tenantProvider}).Build(context.Background(), "tenant-a", baseURL)
			},
		},
		{
			name:                "microsoft",
			expectedRedirectURI: baseURL + "/v2/auth/social/microsoft/callback",
			build: func() (OIDCClient, error) {
				return (&MicrosoftFactory{TenantProvider: tenantProvider}).Build(context.Background(), "tenant-a", baseURL)
			},
		},
		{
			name:                "linkedin",
			expectedRedirectURI: baseURL + "/v2/auth/social/linkedin/callback",
			build: func() (OIDCClient, error) {
				return (&LinkedInFactory{TenantProvider: tenantProvider}).Build(context.Background(), "tenant-a", baseURL)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := tc.build()
			if err != nil {
				t.Fatalf("Build failed: %v", err)
			}
			authURL, err := client.AuthURL(context.Background(), "state-1", "nonce-1")
			if err != nil {
				t.Fatalf("AuthURL failed: %v", err)
			}
			if authURL == "" {
				t.Fatalf("expected non-empty auth URL")
			}
			if !strings.Contains(authURL, url.QueryEscape(tc.expectedRedirectURI)) {
				t.Fatalf("expected redirect_uri %q in auth URL %q", tc.expectedRedirectURI, authURL)
			}
		})
	}
}

func TestGenericOIDCFactory_BuildRequiresAlias(t *testing.T) {
	factory := &GenericOIDCFactory{}
	if _, err := factory.Build(context.Background(), "tenant-a", "https://auth.example.com"); err == nil {
		t.Fatalf("expected alias requirement error")
	}
}

func TestCacheAdapter_BasicOperations(t *testing.T) {
	mem := cache.NewMemory("hj")
	adapter := NewCacheAdapter(mem)

	adapter.Set("social:code:test", []byte("payload"), time.Second)
	value, ok := adapter.Get("social:code:test")
	if !ok || string(value) != "payload" {
		t.Fatalf("expected cache get payload, got ok=%v value=%q", ok, value)
	}

	if err := adapter.Delete("social:code:test"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if _, ok := adapter.Get("social:code:test"); ok {
		t.Fatalf("expected value to be deleted")
	}
}
