package repository

import (
	"context"
	"time"
)

// CacheStats contiene estadísticas del cache.
type CacheStats struct {
	Hits       int64
	Misses     int64
	Keys       int64
	MemoryUsed int64 // bytes
	Latency    time.Duration
}

// CacheRepository define un contrato formal para operaciones de cache.
// Usado para sesiones, códigos temporales, challenges, etc.
type CacheRepository interface {
	// ─── Core Operations ───

	// Get obtiene un valor del cache.
	// Retorna nil, false si no existe o expiró.
	Get(ctx context.Context, key string) ([]byte, bool)

	// Set almacena un valor con TTL.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Delete elimina una clave.
	Delete(ctx context.Context, key string) error

	// Exists verifica si una clave existe.
	Exists(ctx context.Context, key string) (bool, error)

	// ─── Batch Operations ───

	// GetMulti obtiene múltiples valores.
	// Las claves no encontradas no se incluyen en el resultado.
	GetMulti(ctx context.Context, keys []string) (map[string][]byte, error)

	// SetMulti almacena múltiples valores con el mismo TTL.
	SetMulti(ctx context.Context, values map[string][]byte, ttl time.Duration) error

	// DeleteMulti elimina múltiples claves.
	// Retorna el número de claves eliminadas.
	DeleteMulti(ctx context.Context, keys []string) (int, error)

	// ─── Pattern Operations ───

	// DeleteByPrefix elimina todas las claves con un prefijo.
	// Útil para invalidar grupos (ej: "sid:user123:*").
	DeleteByPrefix(ctx context.Context, prefix string) (int, error)

	// ─── Atomic Operations ───

	// GetAndDelete obtiene y elimina atómicamente (one-time tokens).
	GetAndDelete(ctx context.Context, key string) ([]byte, bool, error)

	// SetNX establece solo si la clave no existe (mutex/lock).
	// Retorna true si se estableció, false si ya existía.
	SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)

	// ─── Health ───

	// Ping verifica conexión al backend.
	Ping(ctx context.Context) error

	// Stats retorna estadísticas del cache.
	Stats(ctx context.Context) (*CacheStats, error)

	// Close cierra la conexión.
	Close() error
}

// ─── Key Prefixes (constantes estándar) ───
const (
	CacheKeyPrefixSession      = "sid:"         // Sesiones cookie
	CacheKeyPrefixMFAChallenge = "mfa:token:"   // MFA challenges
	CacheKeyPrefixAuthCode     = "code:"        // Authorization codes
	CacheKeyPrefixSocialCode   = "social:code:" // Social login codes
	CacheKeyPrefixConsentToken = "consent:"     // Consent challenges
	CacheKeyPrefixRateLimit    = "rl:"          // Rate limiting
	CacheKeyPrefixJWKS         = "jwks:"        // JWKS cache
)
