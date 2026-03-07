# HTTP DTOs

> Definiciones de estructuras de datos para Transferencia (Data Transfer Objects).

## Propósito

Este paquete define los contratos de entrada y salida de la API REST. Desacopla los modelos de dominio (`internal/domain`) y persistencia (`internal/store`) de la capa de presentación.

Sus responsabilidades son:
1.  **Contrato API**: Definir exactamente qué JSON entra y sale.
2.  **Validación**: Tags de `json` para serialización.
3.  **Seguridad**: Asegurar que campos internos (IDs de BD, salts, passwords hasheadas) nunca se expongan.

## Estructura

```
internal/http/dto/
├── admin/       # DTOs para /v2/admin/* (Gestión de Tenants, Users, Clients)
├── auth/        # DTOs para /v2/auth/* (Login, Register)
├── health/      # DTOs para /readyz
├── common/      # Estructuras compartidas (Pagination, ID lists)
└── ...
```

## Convenciones

-   **Request DTOs**: Sufijo `Request` (ej: `CreateUserRequest`, `LoginRequest`).
-   **Response DTOs**: Sufijo `Response` (ej: `UserResponse`, `LoginResponse`).
-   **JSON Tags**:
    -   `snake_case` para endpoints orientados a máquinas/OAuth2 (ej: `client_id`, `access_token`).
    -   `camelCase` para endpoints de UI de Admin (ej: `brandColor`, `issuerMode`), alineado con el Frontend React.

## Ejemplo de Uso

```go
// En Controller
func (c *Ctrl) Create(w http.ResponseWriter, r *http.Request) {
    var req dto.CreateUserRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
         // ...
    }
    // ...
}
```

## Dependencias

-   Este paquete **no debe tener dependencias** de otros paquetes internos (salvo tipos primitivos o `time`). Es un paquete "hoja" en el grafo de dependencias.
