# Control Plane Service

> Capa de servicio para la gestión de configuración de Tenants, Clients y Admins.

## Propósito

Este módulo implementa la lógica de negocio del Control Plane. Actúa como intermediario entre los handlers HTTP y la capa de persistencia (Store V2), encargándose de:

1.  **Validaciones**: Reglas de negocio para slugs, clientIDs, redirectURIs, etc.
2.  **Seguridad**: Cifrado automático de secretos (SMTP passwords, DB DSNs, Client Secrets) antes de persistir.
3.  **Orquestación**: Coordinación de operaciones CRUD.
4.  **Defaults**: Provisión de plantillas de email y configuraciones por defecto.

## Estructura

```
internal/controlplane/
├── service.go      # Interface Service, Structs (ClientInput, etc) y Métodos Tenants/Clients
├── admins.go       # Gestión de Administradores y Refresh Tokens
├── defaults.go     # Templates de Email por defecto (ES/EN) y estilos base
└── README.md       # Documentación de arquitectura (existente)
```

## Interface Principal

`Service` expone métodos para gestionar:

-   **Tenants**: CRUD, Settings (SMTP, Auth, etc).
-   **Clients**: CRUD, Cifrado de Secret, Validaciones OAuth/OIDC.
-   **Scopes**: Gestión de permisos.
-   **Claims**: Configuración de claims estándar y custom.
-   **Admins**: Gestión de usuarios administradores globales y de tenant.
-   **Admin Refresh Tokens**: Gestión de sesiones de larga duración para admins.

## Características Clave

### Cifrado de Secretos

El servicio utiliza `internal/security/secretbox` para cifrar campos sensibles antes de enviarlos al Store.

| Campo | Destino Cifrado |
|-------|-----------------|
| `ClientInput.Secret` | `Client.SecretEnc` |
| `TenantSettings.SMTP.Password` | `SMTP.PasswordEnc` |
| `TenantSettings.UserDB.DSN` | `UserDB.DSNEnc` |
| `TenantSettings.Cache.Password` | `Cache.PassEnc` |

### Gestión de Templates

`defaults.go` contiene templates HTML responsive para emails transaccionales (Verify Email, Reset Password, etc.) en Español e Inglés. Estos se inyectan en nuevos tenants por defecto.

### Validaciones

-   **ClientID**: 3-64 caracteres, alfanumérico + `-_`.
-   **RedirectURI**: Debe ser HTTPS o localhost/127.0.0.1.
-   **Slugs**: Validación estricta de formato URL-friendly.

## Dependencias

-   `internal/store`: Capa de persistencia (Data Access Layer).
-   `internal/security/secretbox`: Cifrado autenticado (NaCl SecretBox).
-   `internal/security/token`: Generación de tokens opacos seguros.
-   `internal/domain/repository`: Definiciones de modelos de dominio.

## Ejemplo de Uso

```go
// Inicialización (normalmente en wiring)
cpService := controlplane.NewService(storeMgr)

// Crear un Cliente Confidential
client, err := cpService.CreateClient(ctx, "my-tenant", controlplane.ClientInput{
    Name:     "Backend API",
    ClientID: "backend-service",
    Type:     "confidential",
    // Secret opcional: si se omite, se genera uno seguro automáticamente
})

// El secret generado (plain) está disponible en client.SecretEnc TEMPORALMENTE 
// para mostrarlo al usuario una única vez.
fmt.Println("Client Secret:", client.SecretEnc) 
```

## Ver También

- [internal/store](../store/README.md) - Backend de persistencia.
- [internal/controlplane/README.md](./README.md) - Documento de arquitectura detallado.
