# Logger - Guía de Referencia

Singleton de logging con [Zap](https://github.com/uber-go/zap) para el proyecto.

---

## Inicialización

En `main.go`:

```go
import "github.com/dropDatabas3/hellojohn/internal/observability/logger"

func main() {
    logger.Init(logger.Config{
        Env:         os.Getenv("APP_ENV"),   // "dev" o "prod"
        Level:       os.Getenv("LOG_LEVEL"), // "debug", "info", "warn", "error"
        ServiceName: "hellojohn",            // Opcional
        Version:     "1.0.0",                // Opcional
    })
    defer logger.Sync()
    
    // ...
}
```

---

## Uso Básico

### Sin contexto (singleton)

```go
logger.L().Info("server started", logger.Int("port", 8080))
logger.L().Error("failed to connect", logger.Err(err))
```

### Con contexto (recomendado)

```go
// El logger del contexto ya tiene request_id, method, path, etc.
log := logger.From(ctx)
log.Info("processing request")
log.Debug("user lookup", logger.UserID(userID))
log.Error("failed", logger.Err(err))
```

### SugaredLogger (printf-style)

```go
logger.S().Infof("user %s created", userID)
logger.S().Errorw("failed", "error", err, "user_id", userID)
```

---

## Campos Estándar

### HTTP

| Helper | Campo | Ejemplo |
|--------|-------|---------|
| `RequestID(v)` | `request_id` | Tracking |
| `Method(v)` | `method` | "POST" |
| `Path(v)` | `path` | "/v1/users" |
| `Status(v)` | `status` | 200 |
| `Duration(v)` | `duration` | time.Duration |
| `DurationMs(v)` | `duration_ms` | 45 |
| `Bytes(v)` | `bytes` | 1024 |
| `ClientIP(v)` | `client_ip` | "192.168.1.1" |

### Negocio

| Helper | Campo |
|--------|-------|
| `TenantID(v)` | `tenant_id` |
| `TenantSlug(v)` | `tenant_slug` |
| `UserID(v)` | `user_id` |
| `ClientID(v)` | `client_id` |
| `Email(v)` | `email` |

### Sistema

| Helper | Campo | Uso |
|--------|-------|-----|
| `Component(v)` | `component` | "UserService" |
| `Op(v)` | `op` | "Create" |
| `Layer(v)` | `layer` | "service", "repository" |
| `Err(err)` | `error` | Error |

### Genéricos

| Helper | Descripción |
|--------|-------------|
| `String(k, v)` | Campo string |
| `Int(k, v)` | Campo int |
| `Bool(k, v)` | Campo bool |
| `Any(k, v)` | Cualquier tipo |

---

## Patrones de Uso

### En Handler

```go
func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
    log := logger.From(r.Context()).With(logger.Op("Create"))
    
    // ...
    
    log.Info("user created", logger.UserID(user.ID))
}
```

### En Service

```go
func (s *UserService) Create(ctx context.Context, input CreateUserInput) (*User, error) {
    log := logger.From(ctx).With(
        logger.Layer("service"),
        logger.Op("UserService.Create"),
    )
    
    log.Debug("creating user", logger.Email(input.Email))
    
    user, err := s.repo.Create(ctx, input)
    if err != nil {
        log.Error("failed to create user", logger.Err(err))
        return nil, err
    }
    
    log.Info("user created", logger.UserID(user.ID))
    return user, nil
}
```

### En Repository

```go
func (r *UserRepo) Create(ctx context.Context, input CreateUserInput) (*User, error) {
    log := logger.From(ctx).With(
        logger.Layer("repository"),
        logger.Op("UserRepo.Create"),
    )
    
    log.Debug("inserting user into database")
    
    // ...
}
```

---

## Entornos

### Dev (`APP_ENV=dev`)

- Consola con colores
- Tiempo: `15:04:05.000`
- Caller habilitado
- Sin stacktrace

```
DEBUG [15:04:05.123] creating user  {"email": "test@example.com"}
INFO  [15:04:05.145] user created   {"user_id": "usr_123"}
```

### Prod (`APP_ENV=prod`)

- JSON estructurado
- Tiempo: ISO8601
- Caller habilitado
- Stacktrace en errores

```json
{"level":"info","ts":"2024-01-15T15:04:05.145Z","caller":"service/user.go:45","msg":"user created","user_id":"usr_123"}
```

---

## Variables de Entorno

| Variable | Valores | Default |
|----------|---------|---------|
| `APP_ENV` | `dev`, `prod` | `dev` |
| `LOG_LEVEL` | `debug`, `info`, `warn`, `error` | `info` |

---

## Integración con Middlewares

El middleware `WithLogging()` automáticamente:

1. Crea un logger scoped con `request_id`, `method`, `path`
2. Lo inyecta en el contexto
3. Agrega `tenant_slug` y `user_id` si están disponibles
4. Loguea la finalización del request con status, bytes y duración

```go
mux.Handle("/v1/users", mw.Chain(handler,
    mw.WithRecover(),
    mw.WithRequestID(),
    mw.WithLogging(),  // Inyecta logger en contexto
    // ...
))
```
