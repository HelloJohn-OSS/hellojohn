package repository

import (
	"context"
	"time"
)

// EmailToken representa un token temporal para verificación de email o password reset.
type EmailToken struct {
	ID        string
	TenantID  string
	UserID    string
	Email     string
	Type      EmailTokenType
	TokenHash string
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// EmailTokenType indica el propósito del token.
type EmailTokenType string

const (
	EmailTokenVerification  EmailTokenType = "email_verification"
	EmailTokenPasswordReset EmailTokenType = "password_reset"
)

// CreateEmailTokenInput contiene los datos para crear un token de email.
type CreateEmailTokenInput struct {
	TenantID   string
	UserID     string
	Email      string
	Type       EmailTokenType
	TokenHash  string
	TTLSeconds int
}

// EmailTokenRepository define operaciones sobre tokens de email temporales.
type EmailTokenRepository interface {
	// Create crea un nuevo token de email (verification o password reset).
	// Si ya existe uno activo para el mismo usuario/tipo, lo invalida.
	Create(ctx context.Context, input CreateEmailTokenInput) (*EmailToken, error)

	// GetByHash busca un token por su hash.
	// Retorna ErrNotFound si no existe.
	GetByHash(ctx context.Context, tokenHash string) (*EmailToken, error)

	// Use marca el token como usado (one-time use).
	// Retorna ErrNotFound si no existe o ErrTokenExpired si expiró.
	Use(ctx context.Context, tokenHash string) error

	// DeleteExpired elimina tokens expirados (cleanup job).
	// Retorna el número de tokens eliminados.
	DeleteExpired(ctx context.Context) (int, error)
}
