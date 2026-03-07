package session

import (
	"testing"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/session"
)

func TestApplyTenantCookiePolicy(t *testing.T) {
	t.Parallel()

	secureFalse := false
	cfg := dto.LoginConfig{
		CookieName:   "__Host-sid",
		CookieDomain: "",
		SameSite:     "Lax",
		Secure:       true,
	}

	applyTenantCookiePolicy(&cfg, &repository.CookiePolicy{
		Domain:   "example.com",
		SameSite: "strict",
		Secure:   &secureFalse,
	})

	if cfg.CookieDomain != "example.com" {
		t.Fatalf("expected domain override, got=%q", cfg.CookieDomain)
	}
	if cfg.SameSite != "Strict" {
		t.Fatalf("expected sameSite Strict, got=%q", cfg.SameSite)
	}
	if cfg.Secure {
		t.Fatalf("expected secure override false")
	}
}

func TestApplyTenantCookiePolicyIgnoresInvalidSameSite(t *testing.T) {
	t.Parallel()

	cfg := dto.LoginConfig{
		SameSite: "Lax",
		Secure:   true,
	}

	applyTenantCookiePolicy(&cfg, &repository.CookiePolicy{
		SameSite: "invalid",
	})

	if cfg.SameSite != "Lax" {
		t.Fatalf("invalid sameSite should not override config, got=%q", cfg.SameSite)
	}
}
