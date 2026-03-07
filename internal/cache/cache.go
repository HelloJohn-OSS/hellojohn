// Package cache provee abstracciones para caching con soporte multi-backend.
//
// Soporta:
//   - Memory (in-process, para desarrollo/testing)
//   - Redis (distribuido, para producción)
//
// El cache es tenant-scoped y se accede via TenantDataAccess.Cache().
package cache

import (
	"context"
	"time"
)

// Client define las operaciones de cache.
type Client interface {
	// Get obtiene un valor. Retorna ErrNotFound si no existe.
	Get(ctx context.Context, key string) (string, error)

	// Set guarda un valor con TTL opcional.
	// Si ttl es 0, no expira.
	Set(ctx context.Context, key, value string, ttl time.Duration) error

	// Delete elimina una key.
	Delete(ctx context.Context, key string) error

	// GetDel obtiene y elimina una key atómicamente.
	GetDel(ctx context.Context, key string) (string, error)

	// Exists verifica si una key existe.
	Exists(ctx context.Context, key string) (bool, error)

	// Ping verifica la conexión.
	Ping(ctx context.Context) error

	// Close cierra la conexión.
	Close() error

	// Stats retorna estadísticas del cache.
	Stats(ctx context.Context) (Stats, error)
}

// Stats contiene estadísticas del cache.
type Stats struct {
	Driver     string
	Keys       int64
	UsedMemory string
	Hits       int64
	Misses     int64
}

// Config configuración para crear un cliente de cache.
type Config struct {
	Driver   string // "memory" | "redis"
	Host     string
	Port     int
	Password string
	DB       int
	Prefix   string // Prefijo para todas las keys
}

// Errores de cache.
var (
	ErrNotFound = errNotFound{}
)

type errNotFound struct{}

func (e errNotFound) Error() string { return "cache: key not found" }

// IsNotFound verifica si el error es porque la key no existe.
func IsNotFound(err error) bool {
	_, ok := err.(errNotFound)
	return ok
}

// New crea un cliente de cache según la configuración.
func New(cfg Config) (Client, error) {
	switch cfg.Driver {
	case "redis":
		return NewRedis(cfg)
	case "memory", "":
		return NewMemory(cfg.Prefix), nil
	default:
		return NewMemory(cfg.Prefix), nil
	}
}
