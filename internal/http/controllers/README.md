# HTTP Controllers V2

> Capa de manejo de peticiones HTTP. Responsable de parsear requests, invocar servicios y formatear respuestas.

## Propósito

Este paquete implementa la capa de entrada del servidor API. Sigue estrictamente el patrón **Controller**, delegando toda la lógica de negocio a la capa de **Services**.

Sus responsabilidades son:
1.  **Transporte**: Parsear Body (JSON/Form), Headers, Query Params.
2.  **Validación Básica**: Verificar Content-Type, formato de JSON.
3.  **Orquestación**: Llamar al Service correspondiente.
4.  **Mapeo de Errores**: Traducir errores de dominio (`svc.ErrInvalidCredentials`) a códigos HTTP (`401 Unauthorized`).
5.  **Respuesta**: Serializar DTOs de respuesta a JSON.

## Estructura

```
internal/http/controllers/
├── controllers.go       # Aggregator principal (Composition Root)
├── admin/               # Endpoints administrativos (/v2/admin/*)
├── auth/                # Endpoints de autenticación (/v2/auth/*)
├── oidc/                # Endpoints OIDC (/.well-known/*, /userinfo)
├── health/              # Health checks (/readyz, /livez)
├── social/              # Social Login (/v2/auth/social/*)
└── ...
```

## Patrón de Implementación

Cada controller sigue esta estructura estándar:

```go
type MyController struct {
    service svc.MyService
}

func NewMyController(s svc.MyService) *MyController {
    return &MyController{service: s}
}

func (c *MyController) HandleAction(w http.ResponseWriter, r *http.Request) {
    // 1. Parsear Request
    var req dto.MyRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        httperrors.WriteError(w, httperrors.ErrInvalidJSON)
        return
    }

    // 2. Llamar al Service
    res, err := c.service.DoAction(r.Context(), req)
    if err != nil {
        // 3. Mapear Error
        // (Ver helpers/errors.go o función writeError local)
        c.writeError(w, err)
        return
    }

    // 4. Escribir Respuesta
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(res)
}
```

## Manejo de Errores

Los controllers **NO** deben retornar errores genéricos 500 si el error es conocido. Se usan helpers como `httperrors.WriteError` o switches locales para mapear errores de servicio.

## Dependencias

-   **Entrantes**: `internal/http/services` (interfaces), `internal/http/dto`.
-   **Salientes**: `internal/http/services` (implementación inyectada), `internal/http/errors`, `internal/observability/logger`.

## Ver También

-   [internal/http/services](../services/README.md) - Lógica de negocio.
-   [internal/http/dto](../dto/README.md) - Estructuras de datos de transferencia.
