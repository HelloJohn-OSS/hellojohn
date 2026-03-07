package password

import "strings"

// PersonalInfoRule impide que la contraseña contenga partes del email o nombre del
// usuario. Las comparaciones son case-insensitive; para nombres, solo se evalúan
// palabras de >3 caracteres para evitar falsos positivos con iniciales cortas.
type PersonalInfoRule struct{}

func (r PersonalInfoRule) Name() string { return "personal_info" }

func (r PersonalInfoRule) Validate(password string, ctx PolicyContext) *Violation {
	lowerPass := strings.ToLower(password)

	// Validar contra email (parte local, antes del @)
	if ctx.Email != "" {
		parts := strings.SplitN(ctx.Email, "@", 2)
		emailPrefix := strings.ToLower(parts[0])
		if len(emailPrefix) > 2 && strings.Contains(lowerPass, emailPrefix) {
			return &Violation{
				Rule:    r.Name(),
				Message: "Password cannot contain part of your email address.",
			}
		}
	}

	// Validar contra nombre (cada palabra individual)
	if ctx.Name != "" {
		words := strings.Fields(ctx.Name)
		for _, w := range words {
			if len(w) > 3 && strings.Contains(lowerPass, strings.ToLower(w)) {
				return &Violation{
					Rule:    r.Name(),
					Message: "Password cannot contain your personal name.",
				}
			}
		}
	}

	return nil
}
