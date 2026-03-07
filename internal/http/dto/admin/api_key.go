package admin

import "time"

// CreateAPIKeyRequest es el body de POST /v2/admin/api-keys
type CreateAPIKeyRequest struct {
	Name      string  `json:"name"`                 // requerido, 1-100 chars
	Scope     string  `json:"scope"`                // "admin"|"readonly"|"cloud"|"tenant:{slug}"
	ExpiresIn *string `json:"expires_in,omitempty"` // "24h", "7d", "30d" — nil=nunca expira
}

// CreateAPIKeyResult es la respuesta de POST /v2/admin/api-keys
// CRÍTICO: Token solo se retorna en la creación. Después NUNCA.
type CreateAPIKeyResult struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Token     string     `json:"token"`      // El token en claro — solo aquí, una vez
	KeyPrefix string     `json:"key_prefix"` // Para identificación visual futura
	Scope     string     `json:"scope"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// APIKeyInfo es la representación de una key SIN el token (para listing)
type APIKeyInfo struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	KeyPrefix  string     `json:"key_prefix"`
	Scope      string     `json:"scope"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	IsActive   bool       `json:"is_active"`
}

// RotateAPIKeyResult es la respuesta de POST /v2/admin/api-keys/{id}/rotate
type RotateAPIKeyResult struct {
	OldKeyID string             `json:"old_key_id"` // ID de la key revocada
	NewKey   CreateAPIKeyResult `json:"new_key"`
}
