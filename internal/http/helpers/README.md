# HTTP Helpers

> Utilidades compartidas para handlers HTTP.

## Propósito

Este paquete provee funciones auxiliares para tareas comunes en la capa HTTP, evitando la repetición de código en Controllers y Middlewares.

Sus responsabilidades incluyen:
1.  **Context Management**: Inyección y extracción de dependencias (`store`, `tenant`, `user`) del `context.Context`.
2.  **I/O**: Lectura y escritura de JSON estandarizada.
3.  **Cookies**: Construcción segura de cookies (HttpOnly, Secure, SameSite).
4.  **JWT Claims**: Utilidades para inyectar claims de sistema (`sysclaims`).

## Estructura

```
internal/http/helpers/
├── json.go        # ReadJSON, WriteJSON, WriteErrorJSON
├── cookies.go     # BuildCookie, BuildDeletionCookie
├── deps.go        # RequestDeps, TenantDeps (V2 Standard)
├── tenant_ctx.go  # Context helpers de bajo nivel (legacy compat)
└── sysclaims.go   # Inyección de claims de sistema (Roles, Permisos)
```

## Uso

### JSON

```go
// Leer body
var req dto.MyRequest
if !helpers.ReadJSON(w, r, &req) {
    return // Error ya escrito
}

// Escribir respuesta
helpers.WriteJSON(w, http.StatusOK, response)
```

### Context Dependencies (V2)

```go
// En middleware
ctx = helpers.WithTenant(ctx, tenantDeps)

// En controller
deps := helpers.MustTenantDAL(r) // Retorna store.TenantDataAccess o panic
users, err := deps.Users().List(ctx, ...)
```

## Dependencias

-   `internal/store`: Para interfaces de acceso a datos.
-   `internal/controlplane`: Para tipos de configuración.
-   `internal/jwt`: Para tipos de issuer.

## Notas de Auditoría

-   Existe cierta superposición entre `deps.go` (V2 typed) y `tenant_ctx.go` (key-value simple). Preferir `deps.go` para nuevo código.
