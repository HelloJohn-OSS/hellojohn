# Email Service V2

> Servicio unificado de envío de correos, transaccionales y notificaciones, con soporte multi-tenant y multi-idioma.

## Propósito

Este módulo gestiona toda la comunicación por email de la plataforma. Sus responsabilidades incluyen:
-   **Resolución de Configuración**: Obtener credenciales SMTP específicas por tenant desde el Store V2.
-   **Seguridad**: Descifrado seguro de contraseñas SMTP en tiempo de vuelo.
-   **Renderizado**: Selección de templates según idioma del usuario/tenant con fallback automático.
-   **Envío**: Abstracción del proveedor de envío (SMTP por defecto).

## Estructura

```
internal/email/
├── service.go          # Lógica principal (SendVerification, ResetPassword, etc.)
├── sender_provider.go  # Resolución de SMTP config y construcción de Senders
├── smtp.go             # Implementación de envío SMTP (go-mail)
├── test_template.go    # Templates para emails de prueba de configuración
├── diag.go             # Diagnóstico de errores SMTP
└── types.go            # DTOs y estructuras de datos
```

## Características Clave

### Multi-Tenant & Multi-Idioma
El servicio resuelve automáticamente el tenant y su configuración. Para los templates:
1.  Busca template específico para el idioma del usuario (ej: `fr`).
2.  Si no existe, busca para el idioma default del tenant (ej: `es`).
3.  Si no existe, usa defaults del sistema.

### Seguridad
-   **Cifrado**: Las contraseñas SMTP se almacenan cifradas (`SecretBox`) y solo se descifran en memoria al momento de crear el `Sender`.
-   **TLS**: Soporta `StartTLS`, `SSL/TLS` implícito y modo `Auto`.

### Diagnóstico
El módulo incluye herramientas para categorizar errores SMTP (`diag.go`), distinguiendo entre problemas temporales (red, rate limit) y permanentes (auth, configuración).

## Uso

```go
// 1. Inicialización
emailSvc, _ := emailv2.NewService(emailv2.ServiceConfig{
    DAL: storeMgr,
    MasterKey: os.Getenv("SECRETBOX_MASTER_KEY"),
})

// 2. Enviar email de verificación
err := emailSvc.SendVerificationEmail(ctx, emailv2.SendVerificationRequest{
    TenantSlugOrID: "acme-corp",
    Email:          "user@acme.com",
    Token:          "xyz123",
    // ...
})
```

## Testing SMTP
Se provee un método `TestSMTP` para validar credenciales sin realizar flujos de negocio complejos, útil para el botón "Probar Conexión" en el dashboard de admin.

## Dependencias

-   `internal/store`: Para obtener configuración de tenants.
-   `internal/security/secretbox`: Para descifrar passwords.
-   `github.com/go-mail/mail`: Driver SMTP.

## Ver También

-   [internal/controlplane](../controlplane/README.md): Donde se configura el SMTP del tenant.
