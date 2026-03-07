package admin

// KeyInfoDTO representa una clave para listados.
type KeyInfoDTO struct {
	KID          string  `json:"kid"`
	Algorithm    string  `json:"alg"`
	Use          string  `json:"use"`
	Status       string  `json:"status"`        // "active", "retiring", "revoked"
	CreatedAt    string  `json:"created_at"`
	RetiredAt    *string `json:"retired_at,omitempty"`
	GraceSeconds *int64  `json:"grace_seconds,omitempty"`
	TenantID     string  `json:"tenant_id,omitempty"`
}

// KeyDetailsDTO representa detalles completos de una clave.
type KeyDetailsDTO struct {
	KeyInfoDTO
	PublicKeyJWK map[string]any `json:"public_key_jwk,omitempty"`
}

// RotateKeysRequest para POST /v2/admin/keys/rotate
type RotateKeysRequest struct {
	TenantID     string `json:"tenant_id,omitempty"`
	GraceSeconds int64  `json:"grace_seconds"`
}

// RotateResult respuesta de rotación.
type RotateResult struct {
	KID          string `json:"kid"`
	GraceSeconds int64  `json:"grace_seconds"`
	Message      string `json:"message"`
}
