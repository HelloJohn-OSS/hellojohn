package fs

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// TestSocialProvidersPersistence verifies round-trip persistence of ALL social
// providers through the YAML serialization layer. A tenant model with every
// provider configured is converted to tenantYAML → marshalled → unmarshalled
// → converted back to the domain model. Every field must survive.
func TestSocialProvidersPersistence(t *testing.T) {
	t.Parallel()

	original := &repository.Tenant{
		ID:   "t-uuid-001",
		Slug: "acme",
		Name: "ACME Corp",
		Settings: repository.TenantSettings{
			SocialLoginEnabled: true,
			SocialProviders: &repository.SocialConfig{
				// Google
				GoogleEnabled:   true,
				GoogleClient:    "google-client-id",
				GoogleSecretEnc: "enc|google-secret",
				// GitHub
				GitHubEnabled:   true,
				GitHubClient:    "github-client-id",
				GitHubSecretEnc: "enc|github-secret",
				// Facebook
				FacebookEnabled:   true,
				FacebookClient:    "fb-client-id",
				FacebookSecretEnc: "enc|fb-secret",
				// Discord
				DiscordEnabled:   true,
				DiscordClient:    "discord-client-id",
				DiscordSecretEnc: "enc|discord-secret",
				// Microsoft
				MicrosoftEnabled:   true,
				MicrosoftClient:    "ms-client-id",
				MicrosoftSecretEnc: "enc|ms-secret",
				MicrosoftTenant:    "common",
				// LinkedIn
				LinkedInEnabled:   true,
				LinkedInClient:    "li-client-id",
				LinkedInSecretEnc: "enc|li-secret",
				// Apple
				AppleEnabled:       true,
				AppleClientID:      "com.acme.auth",
				AppleTeamID:        "TEAMID123",
				AppleKeyID:         "KEYID456",
				ApplePrivateKeyEnc: "enc|apple-p8-key",
				// Custom OIDC
				CustomOIDCProviders: []repository.CustomOIDCConfig{
					{
						Alias:           "gitlab",
						Enabled:         true,
						WellKnownURL:    "https://gitlab.acme.com/.well-known/openid-configuration",
						ClientID:        "gitlab-client-id",
						ClientSecretEnc: "enc|gitlab-secret",
						Scopes:          []string{"openid", "email", "profile"},
					},
					{
						Alias:           "keycloak",
						Enabled:         false,
						WellKnownURL:    "https://sso.acme.com/realms/main/.well-known/openid-configuration",
						ClientID:        "kc-client-id",
						ClientSecretEnc: "enc|kc-secret",
						Scopes:          []string{"openid"},
					},
				},
			},
		},
	}

	// Convert to YAML representation
	yamlData := toTenantYAML(original)

	// Marshal to bytes (simulates writing to file)
	raw, err := yaml.Marshal(yamlData)
	if err != nil {
		t.Fatalf("yaml.Marshal failed: %v", err)
	}

	// Unmarshal from bytes (simulates reading from file)
	var restored tenantYAML
	if err := yaml.Unmarshal(raw, &restored); err != nil {
		t.Fatalf("yaml.Unmarshal failed: %v", err)
	}

	// Convert back to domain model
	result := restored.toRepository("acme")

	// Verify all fields
	sp := result.Settings.SocialProviders
	if sp == nil {
		t.Fatal("SocialProviders is nil after round-trip")
	}

	// Google
	assertEqual(t, "GoogleEnabled", sp.GoogleEnabled, true)
	assertEqual(t, "GoogleClient", sp.GoogleClient, "google-client-id")
	assertEqual(t, "GoogleSecretEnc", sp.GoogleSecretEnc, "enc|google-secret")
	// GitHub
	assertEqual(t, "GitHubEnabled", sp.GitHubEnabled, true)
	assertEqual(t, "GitHubClient", sp.GitHubClient, "github-client-id")
	assertEqual(t, "GitHubSecretEnc", sp.GitHubSecretEnc, "enc|github-secret")
	// Facebook
	assertEqual(t, "FacebookEnabled", sp.FacebookEnabled, true)
	assertEqual(t, "FacebookClient", sp.FacebookClient, "fb-client-id")
	assertEqual(t, "FacebookSecretEnc", sp.FacebookSecretEnc, "enc|fb-secret")
	// Discord
	assertEqual(t, "DiscordEnabled", sp.DiscordEnabled, true)
	assertEqual(t, "DiscordClient", sp.DiscordClient, "discord-client-id")
	assertEqual(t, "DiscordSecretEnc", sp.DiscordSecretEnc, "enc|discord-secret")
	// Microsoft
	assertEqual(t, "MicrosoftEnabled", sp.MicrosoftEnabled, true)
	assertEqual(t, "MicrosoftClient", sp.MicrosoftClient, "ms-client-id")
	assertEqual(t, "MicrosoftSecretEnc", sp.MicrosoftSecretEnc, "enc|ms-secret")
	assertEqual(t, "MicrosoftTenant", sp.MicrosoftTenant, "common")
	// LinkedIn
	assertEqual(t, "LinkedInEnabled", sp.LinkedInEnabled, true)
	assertEqual(t, "LinkedInClient", sp.LinkedInClient, "li-client-id")
	assertEqual(t, "LinkedInSecretEnc", sp.LinkedInSecretEnc, "enc|li-secret")
	// Apple
	assertEqual(t, "AppleEnabled", sp.AppleEnabled, true)
	assertEqual(t, "AppleClientID", sp.AppleClientID, "com.acme.auth")
	assertEqual(t, "AppleTeamID", sp.AppleTeamID, "TEAMID123")
	assertEqual(t, "AppleKeyID", sp.AppleKeyID, "KEYID456")
	assertEqual(t, "ApplePrivateKeyEnc", sp.ApplePrivateKeyEnc, "enc|apple-p8-key")
	// Custom OIDC
	if len(sp.CustomOIDCProviders) != 2 {
		t.Fatalf("expected 2 custom OIDC providers, got %d", len(sp.CustomOIDCProviders))
	}
	gl := sp.CustomOIDCProviders[0]
	assertEqual(t, "CustomOIDC[0].Alias", gl.Alias, "gitlab")
	assertEqual(t, "CustomOIDC[0].Enabled", gl.Enabled, true)
	assertEqual(t, "CustomOIDC[0].WellKnownURL", gl.WellKnownURL, "https://gitlab.acme.com/.well-known/openid-configuration")
	assertEqual(t, "CustomOIDC[0].ClientID", gl.ClientID, "gitlab-client-id")
	assertEqual(t, "CustomOIDC[0].ClientSecretEnc", gl.ClientSecretEnc, "enc|gitlab-secret")
	if len(gl.Scopes) != 3 {
		t.Fatalf("expected 3 scopes for gitlab, got %d", len(gl.Scopes))
	}
	kc := sp.CustomOIDCProviders[1]
	assertEqual(t, "CustomOIDC[1].Alias", kc.Alias, "keycloak")
	assertEqual(t, "CustomOIDC[1].Enabled", kc.Enabled, false)
}

// TestSocialProvidersRoundTripDisk verifies persistence through actual disk I/O.
func TestSocialProvidersRoundTripDisk(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	tenantDir := filepath.Join(dir, "acme")
	if err := os.MkdirAll(tenantDir, 0755); err != nil {
		t.Fatal(err)
	}

	original := &repository.Tenant{
		ID:   "t-uuid-002",
		Slug: "acme",
		Name: "ACME",
		Settings: repository.TenantSettings{
			SocialProviders: &repository.SocialConfig{
				GoogleEnabled:      true,
				GoogleClient:       "gid",
				GoogleSecretEnc:    "enc|gsec",
				GitHubEnabled:      true,
				GitHubClient:       "ghid",
				GitHubSecretEnc:    "enc|ghsec",
				AppleEnabled:       true,
				AppleClientID:      "com.test",
				AppleTeamID:        "T1",
				AppleKeyID:         "K1",
				ApplePrivateKeyEnc: "enc|p8",
				CustomOIDCProviders: []repository.CustomOIDCConfig{
					{Alias: "sso", Enabled: true, WellKnownURL: "https://sso.test/.well-known/openid-configuration", ClientID: "sso-id", ClientSecretEnc: "enc|sso-sec"},
				},
			},
		},
	}

	yamlData := toTenantYAML(original)
	raw, err := yaml.Marshal(yamlData)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	tenantFile := filepath.Join(tenantDir, "tenant.yaml")
	if err := os.WriteFile(tenantFile, raw, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Read back
	data, err := os.ReadFile(tenantFile)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var restored tenantYAML
	if err := yaml.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	result := restored.toRepository("acme")
	sp := result.Settings.SocialProviders
	if sp == nil {
		t.Fatal("SocialProviders nil after disk round-trip")
	}

	assertEqual(t, "GoogleEnabled", sp.GoogleEnabled, true)
	assertEqual(t, "GitHubEnabled", sp.GitHubEnabled, true)
	assertEqual(t, "AppleEnabled", sp.AppleEnabled, true)
	assertEqual(t, "AppleTeamID", sp.AppleTeamID, "T1")
	if len(sp.CustomOIDCProviders) != 1 {
		t.Fatalf("expected 1 custom OIDC, got %d", len(sp.CustomOIDCProviders))
	}
	assertEqual(t, "CustomOIDC.Alias", sp.CustomOIDCProviders[0].Alias, "sso")
}

// assertEqual is a generic test helper for comparing values.
func assertEqual[T comparable](t *testing.T, field string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %v, want %v", field, got, want)
	}
}
