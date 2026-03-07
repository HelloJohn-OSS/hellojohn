# Observability

> Paquete centralizado para logging estructurado, métricas y tracing.

## Propósito

Este módulo estandariza cómo la aplicación genera y recolecta telemetría. Su componente principal es el **Logger**, construido sobre [Uber Zap](https://github.com/uber-go/zap), que ofrece alto rendimiento y asignación de memoria mínima.

## Componentes

### 1. Logger (`internal/observability/logger`)

Provee un logger singleton (`logger.L()`) y helpers para inyectar/extraer el logger del `context.Context`.

-   **Dev Mode**: Salida en consola con colores, timestamps legibles.
-   **Prod Mode**: Salida JSON estructurada para ingestión (Elastic, Datadog, etc.).

**Uso Básico:**

```go
// Inicialización (en main.go)
logger.Init(logger.Config{Env: "dev", Level: "debug"})
defer logger.Sync()

// Uso global
logger.Info("app started")

// Uso con Contexto (recomendado en handlers)
log := logger.From(ctx)
log.Info("processing item", logger.String("item_id", id))
```

### 2. Raft Metrics (`internal/observability/raft`)

Exporta métricas de Prometheus para el subsistema de consenso Raft (usado en modo cluster).

-   `raft_apply_latency_ms`: Histograma de latencia de aplicación de logs.
-   `raft_leadership_changes_total`: Contador de cambios de líder.
-   `raft_log_size_bytes`: Tamaño del log de Raft.

## Configuración

El logger se configura mediante `logger.Config` o variables de entorno en el entrypoint:

| Variable | Descripción | Valores | Default |
|----------|-------------|---------|---------|
| `APP_ENV` | Entorno de ejecución | `dev`, `prod` | `dev` |
| `LOG_LEVEL` | Nivel mínimo de log | `debug`, `info`, `warn`, `error` | `info` |

## Extensión

Para agregar nuevos campos al contexto (ej: `tenant_id` en un middleware):

```go
// Middleware
func Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        l := logger.From(r.Context()).With(zap.String("request_id", reqID))
        ctx := logger.ToContext(r.Context(), l)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```
