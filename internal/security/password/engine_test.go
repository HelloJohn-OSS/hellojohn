package password

import (
	"testing"
)

// ─── PolicyEngine Tests ───

func TestPolicyEngine_EmptyRules(t *testing.T) {
	engine := NewPolicyEngine()
	violations := engine.Validate("anything", PolicyContext{})
	if len(violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(violations))
	}
}

func TestPolicyEngine_MultipleViolations(t *testing.T) {
	engine := NewPolicyEngine(
		MinLengthRule{Min: 10},
		RequireUpperRule{Active: true},
		RequireDigitRule{Active: true},
		RequireSymbolRule{Active: true},
	)
	// "abc" fails: too short, no upper, no digit, no symbol
	violations := engine.Validate("abc", PolicyContext{})
	if len(violations) != 4 {
		t.Errorf("expected 4 violations, got %d: %+v", len(violations), violations)
	}
}

func TestPolicyEngine_AllPass(t *testing.T) {
	engine := NewPolicyEngine(
		MinLengthRule{Min: 8},
		RequireUpperRule{Active: true},
		RequireLowerRule{Active: true},
		RequireDigitRule{Active: true},
		RequireSymbolRule{Active: true},
	)
	violations := engine.Validate("MyP@ssw0rd!", PolicyContext{})
	if len(violations) != 0 {
		t.Errorf("expected 0 violations, got %d: %+v", len(violations), violations)
	}
}

// ─── MinLengthRule Tests ───

func TestMinLengthRule_TooShort(t *testing.T) {
	r := MinLengthRule{Min: 8}
	v := r.Validate("short", PolicyContext{})
	if v == nil {
		t.Fatal("expected violation for short password")
	}
	if v.Rule != "min_length" {
		t.Errorf("expected rule 'min_length', got %q", v.Rule)
	}
}

func TestMinLengthRule_ExactLength(t *testing.T) {
	r := MinLengthRule{Min: 5}
	if v := r.Validate("abcde", PolicyContext{}); v != nil {
		t.Errorf("exact length should pass, got violation: %+v", v)
	}
}

func TestMinLengthRule_Disabled(t *testing.T) {
	r := MinLengthRule{Min: 0}
	if v := r.Validate("a", PolicyContext{}); v != nil {
		t.Errorf("min=0 should be disabled, got violation: %+v", v)
	}
}

// ─── MaxLengthRule Tests ───

func TestMaxLengthRule_TooLong(t *testing.T) {
	r := MaxLengthRule{Max: 5}
	v := r.Validate("toolongpassword", PolicyContext{})
	if v == nil {
		t.Fatal("expected violation for too-long password")
	}
}

func TestMaxLengthRule_Disabled(t *testing.T) {
	r := MaxLengthRule{Max: 0}
	if v := r.Validate("anylength", PolicyContext{}); v != nil {
		t.Errorf("max=0 should be disabled, got violation: %+v", v)
	}
}

// ─── RequireUpperRule Tests ───

func TestRequireUpperRule_Missing(t *testing.T) {
	r := RequireUpperRule{Active: true}
	if v := r.Validate("alllowercase123", PolicyContext{}); v == nil {
		t.Fatal("expected violation for missing uppercase")
	}
}

func TestRequireUpperRule_Present(t *testing.T) {
	r := RequireUpperRule{Active: true}
	if v := r.Validate("hasUpper", PolicyContext{}); v != nil {
		t.Errorf("expected no violation, got: %+v", v)
	}
}

func TestRequireUpperRule_Inactive(t *testing.T) {
	r := RequireUpperRule{Active: false}
	if v := r.Validate("nouppers", PolicyContext{}); v != nil {
		t.Errorf("inactive rule should pass, got: %+v", v)
	}
}

// ─── RequireLowerRule Tests ───

func TestRequireLowerRule_Missing(t *testing.T) {
	r := RequireLowerRule{Active: true}
	if v := r.Validate("ALLUPPERCASE123", PolicyContext{}); v == nil {
		t.Fatal("expected violation for missing lowercase")
	}
}

func TestRequireLowerRule_Present(t *testing.T) {
	r := RequireLowerRule{Active: true}
	if v := r.Validate("HASlOWER", PolicyContext{}); v != nil {
		t.Errorf("expected no violation, got: %+v", v)
	}
}

// ─── RequireDigitRule Tests ───

func TestRequireDigitRule_Missing(t *testing.T) {
	r := RequireDigitRule{Active: true}
	if v := r.Validate("NoDigitsHere!", PolicyContext{}); v == nil {
		t.Fatal("expected violation for missing digit")
	}
}

func TestRequireDigitRule_Present(t *testing.T) {
	r := RequireDigitRule{Active: true}
	if v := r.Validate("has1digit", PolicyContext{}); v != nil {
		t.Errorf("expected no violation, got: %+v", v)
	}
}

// ─── RequireSymbolRule Tests ───

func TestRequireSymbolRule_Missing(t *testing.T) {
	r := RequireSymbolRule{Active: true}
	if v := r.Validate("NoSymbols123", PolicyContext{}); v == nil {
		t.Fatal("expected violation for missing symbol")
	}
}

func TestRequireSymbolRule_Present(t *testing.T) {
	r := RequireSymbolRule{Active: true}
	if v := r.Validate("has@symbol", PolicyContext{}); v != nil {
		t.Errorf("expected no violation, got: %+v", v)
	}
}

// ─── PersonalInfoRule Tests ───

func TestPersonalInfoRule_EmailInPassword(t *testing.T) {
	r := PersonalInfoRule{}
	ctx := PolicyContext{Email: "admin@example.com"}
	v := r.Validate("Admin123!", ctx)
	if v == nil {
		t.Fatal("expected violation: password contains email prefix 'admin'")
	}
	if v.Rule != "personal_info" {
		t.Errorf("expected rule 'personal_info', got %q", v.Rule)
	}
}

func TestPersonalInfoRule_NameInPassword(t *testing.T) {
	r := PersonalInfoRule{}
	ctx := PolicyContext{Name: "John Doe"}
	v := r.Validate("MyJohn!456", ctx)
	if v == nil {
		t.Fatal("expected violation: password contains name 'John'")
	}
}

func TestPersonalInfoRule_ShortNameIgnored(t *testing.T) {
	r := PersonalInfoRule{}
	ctx := PolicyContext{Name: "Li Bo"} // words ≤3 chars, should not trigger
	if v := r.Validate("LiboPass123!", ctx); v != nil {
		t.Errorf("short name words (<=3 chars) should be ignored, got: %+v", v)
	}
}

func TestPersonalInfoRule_NoContext(t *testing.T) {
	r := PersonalInfoRule{}
	if v := r.Validate("anything", PolicyContext{}); v != nil {
		t.Errorf("empty context should not trigger, got: %+v", v)
	}
}

func TestPersonalInfoRule_SafePassword(t *testing.T) {
	r := PersonalInfoRule{}
	ctx := PolicyContext{Email: "user@example.com", Name: "Jane Smith"}
	if v := r.Validate("Str0ng!Random#99", ctx); v != nil {
		t.Errorf("safe password should pass, got: %+v", v)
	}
}

// ─── Integration-style: Engine con Personal + Complexity ───

func TestPolicyEngine_PersonalAndComplexity(t *testing.T) {
	engine := NewPolicyEngine(
		MinLengthRule{Min: 8},
		RequireUpperRule{Active: true},
		RequireDigitRule{Active: true},
		PersonalInfoRule{},
	)
	ctx := PolicyContext{Email: "admin@test.com"}

	// "Admin12" falla: length<8 y contiene email prefix 'admin'
	violations := engine.Validate("Admin12", ctx)
	ruleNames := make(map[string]bool)
	for _, v := range violations {
		ruleNames[v.Rule] = true
	}

	if !ruleNames["min_length"] {
		t.Error("expected min_length violation")
	}
	if !ruleNames["personal_info"] {
		t.Error("expected personal_info violation")
	}
}

// ─── Unicode support ───

func TestMinLengthRule_Unicode(t *testing.T) {
	r := MinLengthRule{Min: 5}
	// "contraseña" tiene 10 runes incluyendo ñ
	if v := r.Validate("cóñtr", PolicyContext{}); v != nil {
		t.Errorf("5-rune unicode password should pass min=5, got: %+v", v)
	}
}
