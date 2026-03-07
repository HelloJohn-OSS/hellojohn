package password

import "unicode"

type Policy struct {
	MinLength     int
	RequireUpper  bool
	RequireLower  bool
	RequireDigit  bool
	RequireSymbol bool
}

func (p Policy) Validate(s string) (ok bool, reasons []string) {
	if len([]rune(s)) < p.MinLength {
		reasons = append(reasons, "too_short")
	}
	var hasU, hasL, hasD, hasS bool
	for _, r := range s {
		switch {
		case unicode.IsUpper(r):
			hasU = true
		case unicode.IsLower(r):
			hasL = true
		case unicode.IsDigit(r):
			hasD = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasS = true
		}
	}
	if p.RequireUpper && !hasU {
		reasons = append(reasons, "missing_upper")
	}
	if p.RequireLower && !hasL {
		reasons = append(reasons, "missing_lower")
	}
	if p.RequireDigit && !hasD {
		reasons = append(reasons, "missing_digit")
	}
	if p.RequireSymbol && !hasS {
		reasons = append(reasons, "missing_symbol")
	}
	return len(reasons) == 0, reasons
}
