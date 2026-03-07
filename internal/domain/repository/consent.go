package repository

import (
	"context"
	"time"
)

// Consent representa el consentimiento de un usuario a un client.
type Consent struct {
	ID        string
	UserID    string
	ClientID  string
	TenantID  string
	Scopes    []string
	GrantedAt time.Time
	UpdatedAt time.Time
	RevokedAt *time.Time
}

// ConsentRepository define operaciones sobre user consents.
type ConsentRepository interface {
	// Upsert crea o actualiza un consent, reemplazando los scopes otorgados.
	Upsert(ctx context.Context, tenantID, userID, clientID string, scopes []string) (*Consent, error)

	// Get obtiene el consent de un usuario para un client específico.
	// Retorna ErrNotFound si no existe.
	Get(ctx context.Context, tenantID, userID, clientID string) (*Consent, error)

	// ListByUser lista todos los consents de un usuario.
	// Si activeOnly es true, filtra los revocados.
	ListByUser(ctx context.Context, tenantID, userID string, activeOnly bool) ([]Consent, error)

	// ListAll lista todos los consents del tenant con paginación.
	// Retorna (consents, total, error).
	ListAll(ctx context.Context, tenantID string, limit, offset int, activeOnly bool) ([]Consent, int, error)

	// Revoke revoca un consent (soft delete con timestamp).
	Revoke(ctx context.Context, tenantID, userID, clientID string) error
}
