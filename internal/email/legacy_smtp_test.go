package emailv2

import (
	"testing"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

func TestLegacySMTP(t *testing.T) {
	legacy := &repository.SMTPSettings{
		Host:     "smtp.example.com",
		Port:     587,
		Username: "legacy-user@example.com",
		Password: "secret",
	}

	cfg := legacySMTPtoConfig(legacy)
	if cfg.Provider != ProviderKindSMTP {
		t.Fatalf("expected provider smtp, got %q", cfg.Provider)
	}
	if cfg.FromEmail != legacy.Username {
		t.Fatalf("expected fallback fromEmail=%q, got %q", legacy.Username, cfg.FromEmail)
	}
	if cfg.SMTP == nil || cfg.SMTP.Host != legacy.Host {
		t.Fatalf("expected smtp host %q in provider config", legacy.Host)
	}

	sender, err := BuildSenderFromConfig(cfg, "")
	if err != nil {
		t.Fatalf("expected legacy smtp config to build sender, got err: %v", err)
	}
	if sender == nil {
		t.Fatal("expected non-nil sender")
	}
}
