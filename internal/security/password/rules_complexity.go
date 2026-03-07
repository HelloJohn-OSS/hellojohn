package password

import (
	"fmt"
	"unicode"
)

// ── MinLengthRule ──

// MinLengthRule exige un largo mínimo de caracteres (runes).
type MinLengthRule struct {
	Min int
}

func (r MinLengthRule) Name() string { return "min_length" }

func (r MinLengthRule) Validate(password string, _ PolicyContext) *Violation {
	if r.Min <= 0 {
		return nil // regla desactivada
	}
	if len([]rune(password)) < r.Min {
		return &Violation{
			Rule:    r.Name(),
			Message: fmt.Sprintf("Password must be at least %d characters long.", r.Min),
			Params:  map[string]any{"min": r.Min},
		}
	}
	return nil
}

// ── MaxLengthRule ──

// MaxLengthRule impone un límite superior (previene ataques DoS en hashing).
type MaxLengthRule struct {
	Max int
}

func (r MaxLengthRule) Name() string { return "max_length" }

func (r MaxLengthRule) Validate(password string, _ PolicyContext) *Violation {
	if r.Max <= 0 {
		return nil
	}
	if len([]rune(password)) > r.Max {
		return &Violation{
			Rule:    r.Name(),
			Message: fmt.Sprintf("Password must be at most %d characters long.", r.Max),
			Params:  map[string]any{"max": r.Max},
		}
	}
	return nil
}

// ── RequireUpperRule ──

// RequireUpperRule exige al menos una letra mayúscula.
type RequireUpperRule struct {
	Active bool
}

func (r RequireUpperRule) Name() string { return "require_upper" }

func (r RequireUpperRule) Validate(password string, _ PolicyContext) *Violation {
	if !r.Active {
		return nil
	}
	for _, c := range password {
		if unicode.IsUpper(c) {
			return nil
		}
	}
	return &Violation{
		Rule:    r.Name(),
		Message: "Password must contain at least one uppercase letter.",
	}
}

// ── RequireLowerRule ──

// RequireLowerRule exige al menos una letra minúscula.
type RequireLowerRule struct {
	Active bool
}

func (r RequireLowerRule) Name() string { return "require_lower" }

func (r RequireLowerRule) Validate(password string, _ PolicyContext) *Violation {
	if !r.Active {
		return nil
	}
	for _, c := range password {
		if unicode.IsLower(c) {
			return nil
		}
	}
	return &Violation{
		Rule:    r.Name(),
		Message: "Password must contain at least one lowercase letter.",
	}
}

// ── RequireDigitRule ──

// RequireDigitRule exige al menos un dígito numérico.
type RequireDigitRule struct {
	Active bool
}

func (r RequireDigitRule) Name() string { return "require_digit" }

func (r RequireDigitRule) Validate(password string, _ PolicyContext) *Violation {
	if !r.Active {
		return nil
	}
	for _, c := range password {
		if unicode.IsDigit(c) {
			return nil
		}
	}
	return &Violation{
		Rule:    r.Name(),
		Message: "Password must contain at least one digit.",
	}
}

// ── RequireSymbolRule ──

// RequireSymbolRule exige al menos un carácter especial (puntuación o símbolo).
type RequireSymbolRule struct {
	Active bool
}

func (r RequireSymbolRule) Name() string { return "require_symbol" }

func (r RequireSymbolRule) Validate(password string, _ PolicyContext) *Violation {
	if !r.Active {
		return nil
	}
	for _, c := range password {
		if unicode.IsPunct(c) || unicode.IsSymbol(c) {
			return nil
		}
	}
	return &Violation{
		Rule:    r.Name(),
		Message: "Password must contain at least one special character.",
	}
}
