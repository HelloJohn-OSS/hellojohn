// Package admin contiene DTOs para endpoints administrativos.
package admin

import "time"

// ─── Request DTOs ───

// ListTokensFilter representa los filtros para listar tokens.
type ListTokensFilter struct {
	UserID   *string `json:"user_id,omitempty"`
	ClientID *string `json:"client_id,omitempty"`
	Status   *string `json:"status,omitempty"` // "active", "expired", "revoked"
	Search   *string `json:"search,omitempty"` // Buscar por user email
	Page     int     `json:"page"`
	PageSize int     `json:"page_size"`
}

// RevokeByUserRequest representa la solicitud para revocar tokens por usuario.
type RevokeByUserRequest struct {
	UserID string `json:"user_id"`
}

// RevokeByClientRequest representa la solicitud para revocar tokens por client.
type RevokeByClientRequest struct {
	ClientID string `json:"client_id"`
}

// ─── Response DTOs ───

// TokenResponse representa un token en la respuesta.
type TokenResponse struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	UserEmail string     `json:"user_email,omitempty"`
	ClientID  string     `json:"client_id"`
	IssuedAt  time.Time  `json:"issued_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	Status    string     `json:"status"` // "active", "expired", "revoked"
}

// ListTokensResponse representa la respuesta paginada de tokens.
type ListTokensResponse struct {
	Tokens     []TokenResponse `json:"tokens"`
	TotalCount int             `json:"total_count"`
	Page       int             `json:"page"`
	PageSize   int             `json:"page_size"`
}

// TokenStats representa las estadísticas de tokens.
type TokenStats struct {
	TotalActive      int                `json:"total_active"`
	IssuedToday      int                `json:"issued_today"`
	RevokedToday     int                `json:"revoked_today"`
	AvgLifetimeHours float64            `json:"avg_lifetime_hours"`
	ByClient         []ClientTokenCount `json:"by_client"`
}

// ClientTokenCount representa el conteo de tokens por client.
type ClientTokenCount struct {
	ClientID string `json:"client_id"`
	Count    int    `json:"count"`
}

// RevokeResponse representa la respuesta de revocación masiva.
type RevokeResponse struct {
	RevokedCount int    `json:"revoked_count"`
	Message      string `json:"message,omitempty"`
}
