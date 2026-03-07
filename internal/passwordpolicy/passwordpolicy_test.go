package passwordpolicy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

func TestEffectiveSecurityPolicyDefaults(t *testing.T) {
	p := EffectiveSecurityPolicy(nil)
	if p.PasswordMinLength != DefaultMinLength {
		t.Fatalf("expected default min length %d, got %d", DefaultMinLength, p.PasswordMinLength)
	}
	if !p.RequireUppercase || !p.RequireLowercase || !p.RequireNumbers {
		t.Fatalf("expected secure defaults for uppercase/lowercase/numbers")
	}
}

func TestValidateRejectsWeakPasswordWithDefaults(t *testing.T) {
	violations := Validate("john123", nil, ValidationContext{
		Email: "john@example.com",
		Name:  "John Doe",
	})
	if len(violations) == 0 {
		t.Fatal("expected violations for weak password")
	}
}

func TestValidateAcceptsStrongPassword(t *testing.T) {
	violations := Validate("StrongPass2026!", nil, ValidationContext{
		Email: "john@example.com",
		Name:  "John Doe",
	})
	if len(violations) != 0 {
		t.Fatalf("expected no violations, got %d", len(violations))
	}
}

func TestValidateHonorsBlacklistFile(t *testing.T) {
	tmp := t.TempDir()
	blacklist := filepath.Join(tmp, "blacklist.txt")
	if err := os.WriteFile(blacklist, []byte("StrongPass2026!\n"), 0o600); err != nil {
		t.Fatalf("failed to write blacklist: %v", err)
	}

	violations := Validate("StrongPass2026!", &repository.SecurityPolicy{
		PasswordMinLength:   8,
		RequireUppercase:    true,
		RequireLowercase:    true,
		RequireNumbers:      true,
		RequireSpecialChars: true,
	}, ValidationContext{
		BlacklistPath: blacklist,
	})
	if len(violations) == 0 {
		t.Fatal("expected blacklist violation")
	}
	if violations[0].Rule != "blacklist" {
		t.Fatalf("expected blacklist rule, got %s", violations[0].Rule)
	}
}

func TestHasConfiguredRules(t *testing.T) {
	if HasConfiguredRules(nil) {
		t.Fatal("expected nil policy to be treated as not configured")
	}

	if HasConfiguredRules(&repository.SecurityPolicy{}) {
		t.Fatal("expected empty policy to be treated as not configured")
	}

	if !HasConfiguredRules(&repository.SecurityPolicy{PasswordMinLength: 8}) {
		t.Fatal("expected policy with min length to be configured")
	}
}

func TestDefaultSimpleSecurityPolicy(t *testing.T) {
	p := DefaultSimpleSecurityPolicy()
	if p.PasswordMinLength != DefaultSimpleMinLength {
		t.Fatalf("expected default simple min length %d, got %d", DefaultSimpleMinLength, p.PasswordMinLength)
	}
	if p.RequireUppercase {
		t.Fatal("expected uppercase requirement disabled in simple default policy")
	}
	if !p.RequireLowercase || !p.RequireNumbers {
		t.Fatal("expected lowercase and numbers enabled in simple default policy")
	}
}
