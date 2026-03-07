# HTTP Services

> Capa de Lógica de Negocio (Service Layer) para la API V2.

## Propósito

Este paquete contiene la lógica de negocio pura de la aplicación, desacoplada del transporte HTTP.
Los **Controllers** invocan a estos **Services**, los cuales a su vez orquestan llamadas a:
-   `internal/store` (Datos)
-   `internal/controlplane` (Configuración)
-   `internal/email` (Notificaciones)
-   `internal/jwt` (Seguridad)

## Estructura

```
internal/http/services/
├── services.go        # Composition Root (Wiring)
├── auth/              # Lógica de autenticación (Login, Register...)
├── admin/             # Lógica administrativa (Tenants, Users, RBAC...)
├── oauth/             # Flujos OAuth2 (Authorize, Token)
└── ...
```

## Patrón de Diseño

Cada sub-paquete (dominio) sigue este patrón:
1.  **Interface**: Define el contrato del servicio.
2.  **Implementation**: Struct privado que implementa la interfaz.
3.  **DTOs**: Usa structs de `internal/http/dto` para entrada/salida.
4.  **No HTTP**: No importa `net/http` (salvo casos excepcionales de cookies/headers muy específicos, aunque idealmente se evita).

## Ejemplo de Uso

```go
// En Controller
func (c *AuthController) Login(w http.ResponseWriter, r *http.Request) {
    var req dto.LoginRequest
    // Bind JSON...

    // Call Service
    res, err := c.svc.Login.LoginPassword(ctx, req)
    if err != nil {
        // Map error to HTTP status
        errors.WriteError(w, err)
        return
    }

    // Write response
    helpers.WriteJSON(w, http.StatusOK, res)
}
```
