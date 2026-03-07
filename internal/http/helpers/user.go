package helpers

import (
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// ─────────────────────────────────────────────────────────────────────────────
// USER STATUS HELPERS
// ─────────────────────────────────────────────────────────────────────────────

// IsUserDisabled verifica si un usuario está deshabilitado.
// Un usuario está deshabilitado si:
//   - DisabledAt no es nil (deshabilitado permanentemente)
//   - DisabledUntil no es nil y la fecha aún no pasó (deshabilitado temporalmente)
func IsUserDisabled(user *repository.User) bool {
	if user == nil {
		return false
	}
	now := time.Now()

	// Deshabilitado permanentemente
	if user.DisabledAt != nil {
		return true
	}

	// Deshabilitado temporalmente
	if user.DisabledUntil != nil && now.Before(*user.DisabledUntil) {
		return true
	}

	return false
}

// IsUserEmailVerified verifica si el email del usuario está verificado.
func IsUserEmailVerified(user *repository.User) bool {
	if user == nil {
		return false
	}
	return user.EmailVerified
}
