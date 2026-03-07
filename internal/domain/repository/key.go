package repository

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"time"
)

// SigningKey representa una clave de firma (EdDSA, ECDSA, RSA).
type SigningKey struct {
	ID         string // KID
	TenantID   string // "" para global
	Algorithm  string // "EdDSA", "ES256", "RS256"
	PrivateKey any    // ed25519.PrivateKey, *ecdsa.PrivateKey, etc.
	PublicKey  any    // ed25519.PublicKey, *ecdsa.PublicKey, etc.
	Status     KeyStatus
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	RetiredAt  *time.Time
}

// KeyStatus indica el estado de una clave.
type KeyStatus string

const (
	KeyStatusActive  KeyStatus = "active"
	KeyStatusRetired KeyStatus = "retired"
	KeyStatusRevoked KeyStatus = "revoked"
)

// JWK representa una clave pública en formato JWK (para JWKS endpoint).
type JWK struct {
	KID       string `json:"kid"`
	Kty       string `json:"kty"`
	Use       string `json:"use,omitempty"`
	Alg       string `json:"alg,omitempty"`
	Crv       string `json:"crv,omitempty"`
	X         string `json:"x,omitempty"`
	Y         string `json:"y,omitempty"`
	N         string `json:"n,omitempty"`
	E         string `json:"e,omitempty"`
	ExpiresAt *int64 `json:"exp,omitempty"` // Unix timestamp
}

// JWKS representa un conjunto de claves públicas.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// KeyRepository define operaciones sobre claves criptográficas.
type KeyRepository interface {
	// ─── Lectura ───

	// GetActive obtiene la clave activa para firmar (global o por tenant).
	// tenantSlug vacío = clave global.
	GetActive(ctx context.Context, tenantSlug string) (*SigningKey, error)

	// GetByKID busca una clave por su Key ID.
	GetByKID(ctx context.Context, kid string) (*SigningKey, error)

	// GetJWKS obtiene el JWKS (claves públicas) para un tenant.
	// tenantSlug vacío = JWKS global.
	// Incluye claves active y retired (para verificación de tokens antiguos).
	GetJWKS(ctx context.Context, tenantSlug string) (*JWKS, error)

	// ListAll obtiene todas las claves (active + retired + revoked) con metadata completa.
	// tenantSlug vacío = claves globales.
	// Útil para admin UI que necesita mostrar todas las claves con sus estados.
	ListAll(ctx context.Context, tenantSlug string) ([]*SigningKey, error)

	// ─── Escritura ───

	// Generate genera un nuevo par de claves y lo almacena.
	// La clave anterior se marca como "retired" si existe.
	Generate(ctx context.Context, tenantSlug, algorithm string) (*SigningKey, error)

	// Rotate rota las claves: genera nueva, retira la anterior.
	// gracePeriod indica cuánto tiempo mantener la clave anterior para verificación.
	Rotate(ctx context.Context, tenantSlug string, gracePeriod time.Duration) (*SigningKey, error)

	// Revoke revoca una clave inmediatamente (emergencia).
	Revoke(ctx context.Context, kid string) error

	// ─── Helpers ───

	// ToEdDSA convierte SigningKey a ed25519.PrivateKey si es EdDSA.
	ToEdDSA(key *SigningKey) (ed25519.PrivateKey, error)

	// ToECDSA convierte SigningKey a *ecdsa.PrivateKey si es ES256/ES384/ES512.
	ToECDSA(key *SigningKey) (*ecdsa.PrivateKey, error)
}
