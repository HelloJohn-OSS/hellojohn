package server

import "testing"

func TestLoadGlobalConfigSessionTokenEnabled(t *testing.T) {
	t.Run("defaults to enabled", func(t *testing.T) {
		t.Setenv("FEATURE_SESSION_TOKEN", "")
		t.Setenv("AUTH_FEATURE_SESSION_TOKEN", "")

		cfg := LoadGlobalConfig()
		if !cfg.SessionTokenEnabled {
			t.Fatalf("expected SessionTokenEnabled=true by default")
		}
	})

	t.Run("reads primary feature flag", func(t *testing.T) {
		t.Setenv("FEATURE_SESSION_TOKEN", "false")
		t.Setenv("AUTH_FEATURE_SESSION_TOKEN", "")

		cfg := LoadGlobalConfig()
		if cfg.SessionTokenEnabled {
			t.Fatalf("expected SessionTokenEnabled=false when FEATURE_SESSION_TOKEN=false")
		}
	})

	t.Run("reads fallback feature flag", func(t *testing.T) {
		t.Setenv("FEATURE_SESSION_TOKEN", "")
		t.Setenv("AUTH_FEATURE_SESSION_TOKEN", "false")

		cfg := LoadGlobalConfig()
		if cfg.SessionTokenEnabled {
			t.Fatalf("expected SessionTokenEnabled=false when AUTH_FEATURE_SESSION_TOKEN=false")
		}
	})
}

func TestLoadGlobalConfigFeatures(t *testing.T) {
	t.Setenv("FEATURE_REFRESH_REUSE_DETECTION", "true")
	t.Setenv("FEATURE_CLIENT_PROFILES", "false")
	t.Setenv("FEATURE_HOST_COOKIE_PREFIX", "false")

	cfg := LoadGlobalConfig()
	if !cfg.Features.RefreshTokenReuseDetection {
		t.Fatalf("expected refresh reuse detection feature enabled")
	}
	if cfg.Features.ClientProfiles {
		t.Fatalf("expected client profiles feature disabled")
	}
	if cfg.Features.HostCookiePrefix {
		t.Fatalf("expected host cookie prefix feature disabled")
	}
}
