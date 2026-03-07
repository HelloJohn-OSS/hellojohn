package social

import (
	"context"
	"errors"
	"testing"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

type tenantProviderForClientConfig struct {
	tenant *repository.Tenant
	client *repository.Client
}

func (t tenantProviderForClientConfig) GetTenant(context.Context, string) (*repository.Tenant, error) {
	if t.tenant == nil {
		return nil, errors.New("tenant not found")
	}
	return t.tenant, nil
}

func (t tenantProviderForClientConfig) GetClient(context.Context, string, string) (*repository.Client, error) {
	if t.client == nil {
		return nil, errors.New("client not found")
	}
	return t.client, nil
}

func TestClientConfigService_IsProviderAllowed_AllProviders(t *testing.T) {
	service := NewClientConfigService(ClientConfigDeps{
		TenantProvider: tenantProviderForClientConfig{
			tenant: buildSocialTenant(true),
			client: buildSocialClient([]string{
				"google", "github", "facebook", "discord", "microsoft", "linkedin", "apple", "gitlab", "corp-sso",
			}),
		},
	})

	providers := []string{
		"google", "github", "facebook", "discord", "microsoft", "linkedin", "apple", "gitlab", "corp-sso",
	}
	for _, provider := range providers {
		t.Run(provider, func(t *testing.T) {
			err := service.IsProviderAllowed(context.Background(), "tenant-a", "client-a", provider)
			if err != nil {
				t.Fatalf("expected provider %q to be allowed, got error: %v", provider, err)
			}
		})
	}
}

func TestClientConfigService_IsProviderAllowed_DisabledAndMisconfigured(t *testing.T) {
	tenant := buildSocialTenant(true)
	tenant.Settings.SocialProviders.GitHubEnabled = false
	tenant.Settings.SocialProviders.ApplePrivateKeyEnc = ""

	service := NewClientConfigService(ClientConfigDeps{
		TenantProvider: tenantProviderForClientConfig{
			tenant: tenant,
			client: buildSocialClient([]string{"github", "apple"}),
		},
	})

	if err := service.IsProviderAllowed(context.Background(), "tenant-a", "client-a", "github"); !errors.Is(err, ErrProviderNotAllowed) {
		t.Fatalf("expected ErrProviderNotAllowed for disabled github, got %v", err)
	}
	if err := service.IsProviderAllowed(context.Background(), "tenant-a", "client-a", "apple"); !errors.Is(err, ErrProviderMisconfigured) {
		t.Fatalf("expected ErrProviderMisconfigured for apple, got %v", err)
	}
}

func TestClientConfigService_IsProviderAllowed_UnknownProvider(t *testing.T) {
	service := NewClientConfigService(ClientConfigDeps{
		TenantProvider: tenantProviderForClientConfig{
			tenant: buildSocialTenant(true),
			client: buildSocialClient([]string{"unknown-provider"}),
		},
	})

	err := service.IsProviderAllowed(context.Background(), "tenant-a", "client-a", "unknown-provider")
	if !errors.Is(err, ErrProviderNotAllowed) {
		t.Fatalf("expected ErrProviderNotAllowed, got %v", err)
	}
}

func buildSocialTenant(socialEnabled bool) *repository.Tenant {
	return &repository.Tenant{
		Slug: "tenant-a",
		Settings: repository.TenantSettings{
			SocialLoginEnabled: socialEnabled,
			SocialProviders: &repository.SocialConfig{
				GoogleEnabled:      true,
				GoogleClient:       "google-client",
				GoogleSecretEnc:    "google-secret-enc",
				GitHubEnabled:      true,
				GitHubClient:       "github-client",
				GitHubSecretEnc:    "github-secret-enc",
				FacebookEnabled:    true,
				FacebookClient:     "facebook-client",
				FacebookSecretEnc:  "facebook-secret-enc",
				DiscordEnabled:     true,
				DiscordClient:      "discord-client",
				DiscordSecretEnc:   "discord-secret-enc",
				MicrosoftEnabled:   true,
				MicrosoftClient:    "microsoft-client",
				MicrosoftSecretEnc: "microsoft-secret-enc",
				LinkedInEnabled:    true,
				LinkedInClient:     "linkedin-client",
				LinkedInSecretEnc:  "linkedin-secret-enc",
				AppleEnabled:       true,
				AppleClientID:      "apple-client-id",
				AppleTeamID:        "APPLETEAM01",
				AppleKeyID:         "APPLEKEY01",
				ApplePrivateKeyEnc: "apple-private-key-enc",
				CustomOIDCProviders: []repository.CustomOIDCConfig{
					{
						Alias:           "gitlab",
						WellKnownURL:    "https://gitlab.example.com/.well-known/openid-configuration",
						ClientID:        "gitlab-client",
						ClientSecretEnc: "gitlab-secret-enc",
						Enabled:         true,
					},
					{
						Alias:           "corp-sso",
						WellKnownURL:    "https://sso.example.com/.well-known/openid-configuration",
						ClientID:        "corp-client",
						ClientSecretEnc: "corp-secret-enc",
						Enabled:         true,
					},
				},
			},
		},
	}
}

func buildSocialClient(providers []string) *repository.Client {
	return &repository.Client{
		ClientID:  "client-a",
		Providers: providers,
	}
}
