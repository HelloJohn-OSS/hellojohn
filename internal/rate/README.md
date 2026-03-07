# Rate Limiting

> Implementación de limitación de tasa distribuidos usando Redis.

## Propósito

Este paquete provee mecanismos para limitar la frecuencia de operaciones (requests HTTP, intentos de login, envíos de email, etc.) para proteger el sistema contra abuso y sobrecarga.

## Implementación

El algoritmo utilizado es **Fixed Window Counter** sobre Redis.
-   **Atomicidad**: Usa `INCR` y `EXPIRE` en un pipeline para asegurar operaciones atómicas.
-   **Estado Compartido**: Al usar Redis, los límites se aplican globalmente entre todas las instancias del servicio.

## Componentes

### 1. `RedisLimiter`

Limitador básico con configuración fija (ej: "100 req / 1 min").

```go
limiter := rate.NewRedisLimiter(redisClient, "api:global:", 100, time.Minute)
res, err := limiter.Allow(ctx, "user_123")
if !res.Allowed {
    // 429 Too Many Requests
}
```

### 2. `MultiRedisLimiter`

Permite aplicar límites dinámicos según el contexto (ej: diferentes planes de suscripción).

```go
multi := rate.NewMultiRedisLimiter(redisClient, "api:tenant:")

// Plan Gratuito: 10 req/min
res, _ := multi.AllowWithLimits(ctx, "tenant_A", 10, time.Minute)

// Plan Pro: 1000 req/min
res, _ := multi.AllowWithLimits(ctx, "tenant_B", 1000, time.Minute)
```

## Estructura de Claves Redis

```
{prefix}{key}:{window_start_timestamp}
```

Ejemplo para `prefix="rl:"`, `key="user:1"`, `window=60s`:
`rl:user:1:1678900020` -> `int64 counter` (TTL 60s)

## Resultado (`Result`)

La operación `Allow` retorna un struct con metadata útil para headers HTTP:

| Campo | headers HTTP sugeridos |
|-------|------------------------|
| `Allowed` | (Status 200 vs 429) |
| `Remaining` | `X-RateLimit-Remaining` |
| `RetryAfter` | `Retry-After` (si bloqueado) |
| `WindowTTL` | `X-RateLimit-Reset` |
