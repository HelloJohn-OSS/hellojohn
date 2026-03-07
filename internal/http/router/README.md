# HTTP Router

> Agregador de rutas V2 para la API REST.

## Propósito

Este paquete define el enrutamiento central de la aplicación, utilizando el enrutador estándar mejorado de **Go 1.22** (`http.ServeMux`).

Sus responsabilidades son:
1.  **Registro de Rutas**: Mapear métodos HTTP y paths a controladores.
2.  **Agrupación**: Organizar endpoints por dominio (`auth`, `admin`, `health`, etc.).
3.  **Middleware Chains**: Aplicar middlewares específicos por grupo de rutas (ej: Auth + RateLimit para API, solo Recover para Health).

## Estructura

El punto de entrada es `router.go` -> `RegisterV2Routes`. Desde ahí se delega a archivos específicos por dominio:

```
internal/http/router/
├── router.go          # Entry point (RegisterV2Routes)
├── auth_routes.go     # /v2/auth/* (Login, Register)
├── admin_routes.go    # /v2/admin/* (Tenant management, RBAC)
├── health_routes.go   # /readyz
└── ...
```

## Patrones

### Go 1.22 Routing

Se utiliza el patrón `METHOD /path` nativo de Go 1.22:

```go
mux.Handle("POST /v2/auth/login", handler)
mux.Handle("GET /v2/admin/tenants/{tenant_id}/users/{userId}", handler)
```

### Middleware Helpers

Cada archivo de rutas define helpers para construir la cadena de middleware adecuada:

-   `authHandler(h)`: Para endpoints públicos de auth (RateLimit + Logger).
-   `authedHandler(h)`: Para endpoints protegidos (Auth + RateLimit + Logger).
-   `adminBaseChain(...)`: Cadena compleja para admin (TenantResolution + AdminAuth + RBAC).

## Dependencias

-   `internal/http/controllers`: Manejadores de lógica.
-   `internal/http/middlewares`: Lógica transversal.
-   `net/http`: Router estándar.
