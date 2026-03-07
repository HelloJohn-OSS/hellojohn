package repository

import (
	"context"
	"time"
)

// Scope representa un scope OAuth.
type Scope struct {
	ID          string
	TenantID    string
	Name        string
	Description string
	DisplayName string   // Nombre amigable para consent screen
	Claims      []string // Claims incluidos cuando se otorga este scope
	DependsOn   string   // Scope del que depende (ej: openid)
	System      bool     // true para scopes built-in (openid, email, profile)
	CreatedAt   time.Time
	UpdatedAt   *time.Time // Timestamp de última actualización
}

// ScopeInput contiene los datos para crear/actualizar un scope.
type ScopeInput struct {
	Name        string
	Description string
	DisplayName string
	Claims      []string
	DependsOn   string
	System      bool
}

// ScopeRepository define operaciones sobre OAuth scopes.
type ScopeRepository interface {
	// Create crea un nuevo scope.
	// Retorna ErrConflict si el nombre ya existe.
	Create(ctx context.Context, input ScopeInput) (*Scope, error)

	// GetByName busca un scope por nombre dentro de un tenant.
	GetByName(ctx context.Context, name string) (*Scope, error)

	// List lista todos los scopes de un tenant.
	List(ctx context.Context) ([]Scope, error)

	// Update actualiza un scope existente.
	// El nombre no se puede cambiar para preservar consents existentes.
	Update(ctx context.Context, input ScopeInput) (*Scope, error)

	// Delete elimina un scope.
	// Retorna error si el scope está en uso por algún client.
	Delete(ctx context.Context, scopeID string) error

	// Upsert crea un scope si no existe, o actualiza si ya existe.
	// Retorna el scope resultante.
	Upsert(ctx context.Context, input ScopeInput) (*Scope, error)
}
