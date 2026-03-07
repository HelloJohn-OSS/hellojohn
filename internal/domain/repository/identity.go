package repository

import (
	"context"
	"time"
)

// SocialIdentity representa una identidad social (Google, GitHub, etc).
type SocialIdentity struct {
	ID             string
	UserID         string
	TenantID       string
	Provider       string // "google", "github", etc.
	ProviderUserID string // ID del usuario en el provider
	Email          string
	EmailVerified  bool
	Name           string
	Picture        string
	RawClaims      map[string]any
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// UpsertSocialIdentityInput contiene los datos para crear/actualizar una identidad social.
type UpsertSocialIdentityInput struct {
	TenantID       string
	Provider       string
	ProviderUserID string
	Email          string
	EmailVerified  bool
	Name           string
	Picture        string
	RawClaims      map[string]any
}

// IdentityRepository define operaciones sobre identidades de autenticación.
// Complementa UserRepository para manejar múltiples providers por usuario.
type IdentityRepository interface {
	// GetByProvider busca una identidad por provider y ID del provider.
	// Retorna ErrNotFound si no existe.
	GetByProvider(ctx context.Context, tenantID, provider, providerUserID string) (*SocialIdentity, error)

	// GetByUserID lista todas las identidades de un usuario.
	GetByUserID(ctx context.Context, userID string) ([]SocialIdentity, error)

	// Upsert crea o actualiza una identidad social.
	// Si no existe usuario con ese email, crea uno nuevo.
	// Si existe, vincula la identidad al usuario existente.
	// Retorna el userID (nuevo o existente).
	Upsert(ctx context.Context, input UpsertSocialIdentityInput) (userID string, isNew bool, err error)

	// Link vincula una identidad a un usuario existente.
	// Usado cuando el usuario ya está autenticado y quiere agregar un provider.
	Link(ctx context.Context, userID string, input UpsertSocialIdentityInput) (*SocialIdentity, error)

	// Unlink elimina una identidad de un usuario.
	// Retorna error si es la única identidad del usuario.
	Unlink(ctx context.Context, userID, provider string) error

	// UpdateClaims actualiza los claims raw de una identidad (post-refresh).
	UpdateClaims(ctx context.Context, identityID string, claims map[string]any) error
}
