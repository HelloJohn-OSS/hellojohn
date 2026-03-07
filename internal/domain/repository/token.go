package repository

import (
	"context"
	"time"
)

// RefreshToken representa un token de refresco.
type RefreshToken struct {
	ID          string
	UserID      string
	UserEmail   string // JOIN con app_user (opcional)
	TenantID    string
	ClientID    string // client_id texto (no UUID)
	TokenHash   string
	IssuedAt    time.Time
	ExpiresAt   time.Time
	RotatedFrom *string
	RevokedAt   *time.Time
}

// CreateRefreshTokenInput contiene los datos para crear un refresh token.
type CreateRefreshTokenInput struct {
	TenantID    string
	ClientID    string
	UserID      string
	TokenHash   string
	TTLSeconds  int
	RotatedFrom *string
}

// ListTokensFilter contiene los filtros para listar tokens.
type ListTokensFilter struct {
	UserID   *string // Filtrar por usuario
	ClientID *string // Filtrar por client
	Status   *string // "active", "expired", "revoked"
	Search   *string // Buscar por email de usuario
	Page     int
	PageSize int
}

// TokenStats contiene las estadísticas de tokens.
type TokenStats struct {
	TotalActive      int
	IssuedToday      int
	RevokedToday     int
	AvgLifetimeHours float64
	ByClient         []ClientTokenCount
}

// ClientTokenCount representa el conteo de tokens por client.
type ClientTokenCount struct {
	ClientID string
	Count    int
}

// TokenRepository define operaciones sobre refresh tokens.
type TokenRepository interface {
	// Create crea un nuevo refresh token.
	// Retorna el ID del token creado.
	Create(ctx context.Context, input CreateRefreshTokenInput) (string, error)

	// GetByHash busca un token por su hash.
	// Retorna ErrNotFound si no existe.
	GetByHash(ctx context.Context, tokenHash string) (*RefreshToken, error)

	// GetByID busca un token por su ID.
	// Retorna ErrNotFound si no existe.
	GetByID(ctx context.Context, tokenID string) (*RefreshToken, error)

	// Revoke revoca un token por su ID.
	Revoke(ctx context.Context, tokenID string) error

	// GetFamilyRoot obtiene el root ID de la familia de rotación para un token.
	// Si el token no fue rotado, retorna su propio ID.
	GetFamilyRoot(ctx context.Context, tokenID string) (string, error)

	// RevokeFamily revoca toda la familia de rotación partiendo del root ID.
	RevokeFamily(ctx context.Context, familyRootID string) error

	// RevokeAllByUser revoca todos los tokens de un usuario.
	// Si clientID no está vacío, filtra solo por ese client.
	// Retorna el número de tokens revocados.
	RevokeAllByUser(ctx context.Context, userID, clientID string) (int, error)

	// RevokeAllByClient revoca todos los tokens de un client (todos los usuarios).
	RevokeAllByClient(ctx context.Context, clientID string) error

	// ─── Admin Operations ───

	// List lista tokens con filtros y paginación.
	// Incluye LEFT JOIN con app_user para obtener email.
	List(ctx context.Context, filter ListTokensFilter) ([]RefreshToken, error)

	// Count cuenta el total de tokens que coinciden con los filtros.
	Count(ctx context.Context, filter ListTokensFilter) (int, error)

	// RevokeAll revoca todos los tokens activos.
	// Retorna el número de tokens revocados.
	RevokeAll(ctx context.Context) (int, error)

	// GetStats obtiene estadísticas de tokens.
	GetStats(ctx context.Context) (*TokenStats, error)
}
