package auth

import (
	"strings"
	"testing"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

func TestProvidersServiceBuildStartURL_UsesV2Routes(t *testing.T) {
	service := &providersService{
		deps: ProvidersDeps{
			Providers: ProviderConfig{
				JWTIssuer: "https://auth.example.com",
			},
		},
	}

	client := &repository.Client{
		RedirectURIs: []string{
			"https://app.example.com/callback",
			"https://auth.example.com/v2/auth/social/result",
		},
	}

	startURL := service.buildStartURL("github", "tenant-a", "client-a", "https://app.example.com/callback", client)
	if startURL == "" {
		t.Fatalf("expected start URL to be generated")
	}
	if !strings.Contains(startURL, "/v2/auth/social/github/start?") {
		t.Fatalf("expected v2 social start route, got %s", startURL)
	}
	if strings.Contains(startURL, "/v1/auth/social/") {
		t.Fatalf("unexpected legacy v1 route in %s", startURL)
	}
	if !strings.Contains(startURL, "tenant_id=tenant-a") || !strings.Contains(startURL, "client_id=client-a") {
		t.Fatalf("missing tenant/client query params in %s", startURL)
	}
}

func TestProvidersServiceBuildStartURL_DefaultRedirectUsesV2Result(t *testing.T) {
	service := &providersService{
		deps: ProvidersDeps{
			Providers: ProviderConfig{
				JWTIssuer: "https://auth.example.com/",
			},
		},
	}

	client := &repository.Client{
		RedirectURIs: []string{
			"https://auth.example.com/v2/auth/social/result",
		},
	}

	startURL := service.buildStartURL("google", "tenant-a", "client-a", "", client)
	if startURL == "" {
		t.Fatalf("expected start URL to be generated using default redirect")
	}
	if !strings.Contains(startURL, "redirect_uri=https%3A%2F%2Fauth.example.com%2Fv2%2Fauth%2Fsocial%2Fresult") {
		t.Fatalf("expected default redirect_uri to use v2 result endpoint, got %s", startURL)
	}
}

func TestResolveProviderNames_UsesClientAndCustomAliases(t *testing.T) {
	cfg := &repository.SocialConfig{
		GoogleEnabled: true,
		CustomOIDCProviders: []repository.CustomOIDCConfig{
			{Alias: "corp-sso", Enabled: true},
		},
	}
	client := &repository.Client{
		Providers: []string{"password", "google", "corp-sso", "unknown"},
	}

	names := resolveProviderNames(client, cfg)
	if len(names) != 2 {
		t.Fatalf("expected 2 providers (google + corp-sso), got %v", names)
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "google") || !strings.Contains(joined, "corp-sso") {
		t.Fatalf("unexpected provider resolution: %v", names)
	}
}
