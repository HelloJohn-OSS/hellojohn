// Package admin contiene DTOs para endpoints administrativos.
package admin

import "time"

// ConsentUpsertRequest representa la entrada para crear/actualizar un consent.
type ConsentUpsertRequest struct {
	UserID   string   `json:"user_id"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

// ConsentRevokeRequest representa la entrada para revocar un consent.
type ConsentRevokeRequest struct {
	UserID   string `json:"user_id"`
	ClientID string `json:"client_id"`
	At       string `json:"at,omitempty"` // RFC3339 opcional
}

// ConsentResponse representa un consent en la respuesta.
type ConsentResponse struct {
	ID        string     `json:"id,omitempty"`
	TenantID  string     `json:"tenant_id"`
	UserID    string     `json:"user_id"`
	ClientID  string     `json:"client_id"`
	Scopes    []string   `json:"scopes"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// ConsentListResponse es una lista de consents.
type ConsentListResponse []ConsentResponse
