package repository

import (
	"context"
	"time"
)

// User representa un usuario del sistema.
type User struct {
	ID             string
	TenantID       string
	Email          string
	EmailVerified  bool
	Name           string
	GivenName      string
	FamilyName     string
	Picture        string
	Locale         string
	Language       string // Idioma preferido del usuario ("es", "en"), vacío = usar default del tenant
	Metadata       map[string]any
	CustomFields   map[string]any
	CreatedAt      time.Time
	DisabledAt     *time.Time
	DisabledUntil  *time.Time
	DisabledReason *string
	SourceClientID *string
}

// Identity representa una identidad de autenticación (password, social, etc).
type Identity struct {
	ID             string
	UserID         string
	Provider       string // "password", "google", etc.
	ProviderUserID string
	Email          string
	EmailVerified  bool
	PasswordHash   *string
	CreatedAt      time.Time
}

// CreateUserInput contiene los datos para crear un usuario.
type CreateUserInput struct {
	TenantID     string
	Email        string
	PasswordHash string
	Name         string
	GivenName    string
	FamilyName   string
	Picture      string
	Locale       string
	CustomFields map[string]any
	// SourceClientID indica desde qué client se registró el usuario.
	SourceClientID string
	// Provider indica el método de registro (e.g. "password", "magic_link")
	Provider string
}

// UpdateUserInput contiene los campos actualizables de un usuario.
type UpdateUserInput struct {
	Name           *string
	GivenName      *string
	FamilyName     *string
	Picture        *string
	Locale         *string
	SourceClientID *string
	CustomFields   map[string]any
}

// ListUsersFilter opciones para listar usuarios.
type ListUsersFilter struct {
	Limit  int    // Default 50, max 200
	Offset int    // Default 0
	Search string // Opcional: búsqueda por email o nombre
}

// UserRepository define operaciones sobre usuarios.
type UserRepository interface {
	// GetByEmail busca un usuario por email dentro de un tenant.
	// Retorna ErrNotFound si no existe.
	GetByEmail(ctx context.Context, tenantID, email string) (*User, *Identity, error)

	// GetByID busca un usuario por ID.
	// Retorna ErrNotFound si no existe.
	GetByID(ctx context.Context, userID string) (*User, error)

	// List lista usuarios de un tenant con paginación.
	List(ctx context.Context, tenantID string, filter ListUsersFilter) ([]User, error)

	// Create crea un nuevo usuario con identity de password.
	// Retorna ErrConflict si el email ya existe.
	Create(ctx context.Context, input CreateUserInput) (*User, *Identity, error)

	// CreateBatch inserta mÃºltiples usuarios para imports masivos.
	// created: usuarios insertados con Ã©xito.
	// failed: usuarios descartados por errores por-registro (ej. email duplicado).
	// err: error de infraestructura; aborta el batch.
	CreateBatch(ctx context.Context, tenantID string, users []CreateUserInput) (created, failed int, err error)

	// Update actualiza campos de un usuario.
	Update(ctx context.Context, userID string, input UpdateUserInput) error

	// Delete elimina un usuario por ID.
	// Retorna ErrNotFound si no existe.
	Delete(ctx context.Context, userID string) error

	// Disable deshabilita temporalmente un usuario.
	Disable(ctx context.Context, userID, by, reason string, until *time.Time) error

	// Enable rehabilita un usuario deshabilitado.
	Enable(ctx context.Context, userID, by string) error

	// CheckPassword verifica si el password coincide con el hash.
	// Este método no accede a la BD, solo hace la comparación.
	CheckPassword(hash *string, password string) bool

	// SetEmailVerified marca el email de un usuario como verificado o no.
	SetEmailVerified(ctx context.Context, userID string, verified bool) error

	// UpdatePasswordHash actualiza el hash del password en la identity "password".
	UpdatePasswordHash(ctx context.Context, userID, newHash string) error

	// ListPasswordHistory retorna los hashes históricos más recientes (más nuevo primero).
	// Se usa para validar políticas de no-reutilización (maxHistory).
	ListPasswordHistory(ctx context.Context, userID string, limit int) ([]string, error)

	// RotatePasswordHash actualiza el hash actual y persiste el hash anterior en password_history
	// dentro de una transacción atómica. keepHistory define cuántos hashes históricos conservar.
	RotatePasswordHash(ctx context.Context, userID, newHash string, keepHistory int) error
}
