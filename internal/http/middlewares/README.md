# HTTP Middlewares

> Componentes transversales para el manejo de peticiones HTTP.

## Propósito

Este paquete implementa la lógica de "pipeline" que se ejecuta antes y después de los Controllers. Gestiona preocupaciones transversales (Cross-Cutting Concerns) como autenticación, logging, seguridad y resolución de contexto.

## Middlewares Principales

### 1. Tenant Resolution (`tenant.go`)
Identifica el tenant actual basado en la ruta, subdominio o headers.
-   **Resolvers**: `PathValue`, `Subdomain`, `Header`.
-   **Acción**: Carga el `TenantDataAccess` y lo inyecta en el contexto.

```go
// Uso: /v2/admin/tenants/{tenant_id}/...
mux.Handle("/v2/admin/tenants/{tenant_id}/", mw.Chain(
    mw.WithTenantResolution(dal, false), // false = obligatorio
    mw.RequireTenantDB(),
)(adminHandler))
```

### 2. Authentication (`auth.go`)
Valida tokens JWT (Bearer) y extrae claims.
-   **RequireAuth**: Falla (401) si no hay token válido.
-   **OptionalAuth**: Permite requests anónimos pero inyecta claims si el token es válido.

### 3. Logging (`logging.go`)
Registra cada request con structured logging, incluyendo duración, status code y metadatos (request_id, tenant_id).

### 4. Rate Limiting (`rate.go`)
Protege la API contra abuso.
-   Key por defecto: `IP + Path + ClientID`.
-   Optimizado para no leer body en rutas administrativas.

### 5. CORS (`cors.go`)
Maneja headers `Access-Control-*` para permitir peticiones cross-origin seguras.

## Orden Recomendado

```go
chain := []mw.Middleware{
    mw.WithRecover(),           // 1. Pánico no tumba el server
    mw.WithRequestID(),         // 2. Traceability
    mw.WithLogging(),           // 3. Observabilidad
    mw.WithCORS(...),           // 4. Seguridad Browser
    mw.WithRateLimit(...),      // 5. Protección DoS
    mw.WithTenantResolution(),  // 6. Contexto de Negocio
    mw.RequireAuth(),           // 7. Seguridad Auth
}
```
