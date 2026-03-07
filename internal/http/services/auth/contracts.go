// Package auth contiene contracts para servicios de autenticación.
package auth

import (
	"context"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
)

// LoginService define las operaciones de login.
type LoginService interface {
	// LoginPassword autentica un usuario con email/password.
	// Devuelve tokens o indica que MFA es requerido.
	LoginPassword(ctx context.Context, in dto.LoginRequest) (*dto.LoginResult, error)
}

// ClaimsHook permite extender claims del token (CEL/webhook/etc).
// Por defecto es no-op. Implementar cuando se migre la feature.
type ClaimsHook interface {
	ApplyAccess(ctx context.Context, tenantID, clientID, userID string, scopes, amr []string, std, custom map[string]any) (map[string]any, map[string]any)
}

// NoOpClaimsHook es el hook por defecto que no modifica claims.
type NoOpClaimsHook struct{}

func (NoOpClaimsHook) ApplyAccess(_ context.Context, _, _, _ string, _, _ []string, std, custom map[string]any) (map[string]any, map[string]any) {
	return std, custom
}
