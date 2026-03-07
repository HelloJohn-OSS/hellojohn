package admin

import (
	"encoding/base64"
	"testing"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	"github.com/dropDatabas3/hellojohn/internal/security/secretbox"
)

func setSecretboxMasterKeyForAdminTests(t *testing.T) {
	t.Helper()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	t.Setenv("SECRETBOX_MASTER_KEY", base64.StdEncoding.EncodeToString(key))
	secretbox.UnsafeResetSecretBoxForTests()
	if _, err := secretbox.Encrypt("probe"); err != nil {
		t.Fatalf("probe encrypt failed after setting key: %v", err)
	}
}

func TestEncryptTenantSecrets_PreservesExistingSocialSecretsWhenNoPlainInput(t *testing.T) {
	settings := &repository.TenantSettings{
		SocialProviders: &repository.SocialConfig{
			GoogleSecretEnc:    "enc-google-existing",
			GitHubSecretEnc:    "enc-github-existing",
			MicrosoftSecretEnc: "enc-ms-existing",
			CustomOIDCProviders: []repository.CustomOIDCConfig{
				{Alias: "corp", ClientSecretEnc: "enc-corp-existing"},
			},
		},
	}

	if err := encryptTenantSecrets(settings, ""); err != nil {
		t.Fatalf("encryptTenantSecrets returned error: %v", err)
	}

	if got := settings.SocialProviders.GoogleSecretEnc; got != "enc-google-existing" {
		t.Fatalf("google secret enc should be preserved, got %q", got)
	}
	if got := settings.SocialProviders.GitHubSecretEnc; got != "enc-github-existing" {
		t.Fatalf("github secret enc should be preserved, got %q", got)
	}
	if got := settings.SocialProviders.MicrosoftSecretEnc; got != "enc-ms-existing" {
		t.Fatalf("microsoft secret enc should be preserved, got %q", got)
	}
	if got := settings.SocialProviders.CustomOIDCProviders[0].ClientSecretEnc; got != "enc-corp-existing" {
		t.Fatalf("custom oidc secret enc should be preserved, got %q", got)
	}
}

func TestMapDTOToTenantSettings_IgnoresInjectedSocialSecretEncFields(t *testing.T) {
	existing := &repository.TenantSettings{
		SocialProviders: &repository.SocialConfig{
			GoogleSecretEnc: "enc-google-existing",
			GitHubSecretEnc: "enc-github-existing",
		},
	}

	req := dto.UpdateTenantSettingsRequest{
		SocialProviders: &dto.SocialProvidersConfig{
			GoogleEnabled:   true,
			GoogleSecretEnc: "enc-google-injected",
			GitHubEnabled:   true,
			GitHubSecretEnc: "enc-github-injected",
		},
	}

	got := mapDTOToTenantSettings(&req, existing)
	if got.SocialProviders == nil {
		t.Fatalf("expected social providers in result")
	}

	if got.SocialProviders.GoogleSecretEnc != "enc-google-existing" {
		t.Fatalf("google secret enc must keep existing value, got %q", got.SocialProviders.GoogleSecretEnc)
	}
	if got.SocialProviders.GitHubSecretEnc != "enc-github-existing" {
		t.Fatalf("github secret enc must keep existing value, got %q", got.SocialProviders.GitHubSecretEnc)
	}
}

func TestMapDTOToTenantSettings_PreservesCustomOIDCSecretEncOnPartialUpdate(t *testing.T) {
	existing := &repository.TenantSettings{
		SocialProviders: &repository.SocialConfig{
			CustomOIDCProviders: []repository.CustomOIDCConfig{
				{
					Alias:           "corp",
					WellKnownURL:    "https://idp.example.com/.well-known/openid-configuration",
					ClientID:        "old-client",
					ClientSecretEnc: "enc-corp-existing",
					Enabled:         true,
				},
			},
		},
	}

	req := dto.UpdateTenantSettingsRequest{
		SocialProviders: &dto.SocialProvidersConfig{
			CustomOIDCProviders: []dto.CustomOIDCProviderDTO{
				{
					Alias:        "corp",
					WellKnownURL: "https://idp.example.com/.well-known/openid-configuration",
					ClientID:     "new-client",
					Enabled:      true,
				},
			},
		},
	}

	got := mapDTOToTenantSettings(&req, existing)
	if got.SocialProviders == nil || len(got.SocialProviders.CustomOIDCProviders) != 1 {
		t.Fatalf("expected one custom oidc provider in result")
	}

	provider := got.SocialProviders.CustomOIDCProviders[0]
	if provider.ClientSecretEnc != "enc-corp-existing" {
		t.Fatalf("custom oidc secret enc should be preserved, got %q", provider.ClientSecretEnc)
	}
	if provider.ClientID != "new-client" {
		t.Fatalf("expected client id to be updated, got %q", provider.ClientID)
	}
}

func TestMapDTOToTenantSettings_CustomOIDCPlainSecretEncryptsAndOverrides(t *testing.T) {
	setSecretboxMasterKeyForAdminTests(t)

	existing := &repository.TenantSettings{
		SocialProviders: &repository.SocialConfig{
			CustomOIDCProviders: []repository.CustomOIDCConfig{
				{
					Alias:           "corp",
					ClientSecretEnc: "enc-corp-existing",
				},
			},
		},
	}

	req := dto.UpdateTenantSettingsRequest{
		SocialProviders: &dto.SocialProvidersConfig{
			CustomOIDCProviders: []dto.CustomOIDCProviderDTO{
				{
					Alias:        "corp",
					WellKnownURL: "https://idp.example.com/.well-known/openid-configuration",
					ClientID:     "client-new",
					ClientSecret: "new-plain-secret",
					Enabled:      true,
				},
			},
		},
	}

	got := mapDTOToTenantSettings(&req, existing)
	if got.SocialProviders == nil || len(got.SocialProviders.CustomOIDCProviders) != 1 {
		t.Fatalf("expected one custom oidc provider in result")
	}

	enc := got.SocialProviders.CustomOIDCProviders[0].ClientSecretEnc
	if enc == "" {
		t.Fatalf("expected encrypted custom oidc secret")
	}
	if enc == "enc-corp-existing" {
		t.Fatalf("expected encrypted custom oidc secret to override existing value")
	}
}
