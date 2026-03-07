# HTTP Errors

> Estandarización de errores para la API REST V2.

## Propósito

Este paquete provee:
1.  **Tipos de Error**: Estructura `AppError` que encapsula código, mensaje, detalle y status HTTP.
2.  **Mapeo**: Conversión de errores de Go (`error`) a respuestas HTTP JSON.
3.  **Catálogo**: Definición centralizada de errores comunes (400, 401, 403, 404, etc.).

## Estructura

```go
type AppError struct {
    Code       string `json:"code"`
    Message    string `json:"message"`
    Detail     string `json:"detail,omitempty"`
    HTTPStatus int    `json:"-"`
    Err        error  `json:"-"` // Causa original
}
```

## Uso

```go
// 1. Devolver error predefinido
if req.Email == "" {
    httperrors.WriteError(w, httperrors.ErrMissingFields)
    return
}

// 2. Agregar detalle/contexto
if !isValid(email) {
    httperrors.WriteError(w, httperrors.ErrInvalidFormat.WithDetail("invalid email"))
    return
}

// 3. Wrappear error original (interno)
if err := db.Query(); err != nil {
    // Se loguea el error original, al cliente le llega 500 Internal Server Error
    httperrors.WriteError(w, httperrors.ErrInternalServerError.WithCause(err))
    return
}
```

## Respuesta JSON

```json
{
  "code": "INVALID_FORMAT",
  "message": "El formato de uno o más campos es inválido.",
  "detail": "invalid email"
}
```
