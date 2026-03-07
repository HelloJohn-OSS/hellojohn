# Cache - Multi-Backend Caching

> Abstracción de cache con soporte para Memory (desarrollo) y Redis (producción)

## Propósito

Provee una interfaz unificada de cache que permite:
- **Memory backend**: Para desarrollo y testing (in-process)
- **Redis backend**: Para producción (distribuido, persistente)

El cache es usado internamente por el DAL, OAuth, Social login y MFA para almacenar datos temporales como tokens de estado, sesiones parciales, y rate limiting.

## Estructura

```
internal/cache/
├── cache.go     # Interface Client + factory New()
├── memory.go    # Implementación in-memory
├── redis.go     # Implementación Redis (v9)
└── redis/
    └── redis.go # Implementación alternativa legacy (bytes)
```

## Interface Principal

```go
type Client interface {
    Get(ctx, key) (string, error)
    Set(ctx, key, value, ttl) error
    Delete(ctx, key) error
    Exists(ctx, key) (bool, error)
    Ping(ctx) error
    Close() error
    Stats(ctx) (Stats, error)
}
```

## Configuración

```go
type Config struct {
    Driver   string // "memory" | "redis"
    Host     string
    Port     int
    Password string
    DB       int
    Prefix   string // Prefijo para todas las keys
}

// Factory
client, err := cache.New(Config{
    Driver: "redis",
    Host:   "localhost",
    Port:   6379,
})
```

## Backends

### Memory (default)

- Thread-safe via `sync.RWMutex`
- TTL con lazy expiration
- `Cleanup()` para purgar expirados manualmente
- Hit/Miss stats

### Redis

- Usa `github.com/redis/go-redis/v9`
- Connection pooling automático
- Stats de memoria y keys desde Redis INFO

## Dependencias

### Consumidores
- `internal/store` (manager, factory, infra)
- `internal/http/services/oauth` (state cache)
- `internal/http/services/social` (state cache)
- `internal/http/services/auth` (MFA challenges)
- `internal/http/server/wiring` (inicialización)

### Externas
- `github.com/redis/go-redis/v9`

## ⚠️ Código Duplicado

Existe `internal/cache/redis/redis.go` con una implementación alternativa más simple (bytes en lugar de string). Considerar unificar o eliminar.

## Ver También

- [internal/store](../store/README.md) - Principal consumidor
