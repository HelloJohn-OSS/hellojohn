# Package `internal/email/v2`

Servicio de email unificado para HelloJohn, construido sobre Store V2 con soporte multi-tenant y multi-idioma.

---

## Índice

- [Arquitectura](#arquitectura)
- [Instalación](#instalación)
- [Interfaces](#interfaces)
- [Types (DTOs)](#types-dtos)
- [Service](#service)
- [SenderProvider](#senderprovider)
- [SMTPSender](#smtpsender)
- [Diagnóstico de Errores](#diagnóstico-de-errores)
- [Templates Multi-idioma](#templates-multi-idioma)
- [Ejemplos de Uso](#ejemplos-de-uso)

---

## Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                         Service                                  │
│  (SendVerificationEmail, SendPasswordResetEmail, TestSMTP...)   │
├─────────────────────────────────────────────────────────────────┤
│                      SenderProvider                              │
│         (Resuelve tenant → obtiene config SMTP → Sender)        │
├─────────────────────────────────────────────────────────────────┤
│                       SMTPSender                                 │
│              (Implementación real de envío SMTP)                │
├─────────────────────────────────────────────────────────────────┤
│                    Store V2 DAL                                  │
│       (Acceso a tenants, settings, templates via FS/PG)         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Instalación

```go
import emailv2 "github.com/dropDatabas3/hellojohn/internal/email/v2"
```

### Dependencias

- `store/v2` - Data Access Layer
- `internal/security/secretbox` - Descifrado de passwords SMTP
- `internal/observability/logger` - Logging estructurado
- `github.com/go-mail/mail` - Envío SMTP

### Variables de Entorno Requeridas

| Variable | Descripción |
|----------|-------------|
| `SECRETBOX_MASTER_KEY` | Clave maestra hex-encoded (32 bytes) para descifrar passwords SMTP |

---

## Interfaces

### `Sender`

Interfaz básica para envío de emails.

```go
type Sender interface {
    // Send envía un email con contenido HTML y texto plano.
    // El destinatario recibe ambas versiones como multipart/alternative.
    Send(to, subject, htmlBody, textBody string) error
}
```

### `SenderProvider`

Resuelve un `Sender` configurado para un tenant específico.

```go
type SenderProvider interface {
    // GetSender obtiene un Sender configurado para el tenant especificado.
    // tenantSlugOrID puede ser UUID o slug del tenant.
    GetSender(ctx context.Context, tenantSlugOrID string) (Sender, error)
}
```

### `Service`

Interfaz principal del servicio de email.

```go
type Service interface {
    // GetSender obtiene un Sender configurado para el tenant.
    GetSender(ctx context.Context, tenantSlugOrID string) (Sender, error)
    
    // SendVerificationEmail envía un email de verificación.
    SendVerificationEmail(ctx context.Context, req SendVerificationRequest) error
    
    // SendPasswordResetEmail envía un email de reset de password.
    SendPasswordResetEmail(ctx context.Context, req SendPasswordResetRequest) error
    
    // SendNotificationEmail envía una notificación genérica.
    SendNotificationEmail(ctx context.Context, req SendNotificationRequest) error
    
    // TestSMTP prueba la configuración SMTP de un tenant.
    TestSMTP(ctx context.Context, tenantSlugOrID, recipientEmail string, override *SMTPConfig) error
}
```

---

## Types (DTOs)

### Request DTOs

```go
// SendVerificationRequest - Datos para email de verificación
type SendVerificationRequest struct {
    TenantSlugOrID string        // UUID o slug del tenant
    UserID         string        // UUID del usuario
    Email          string        // Email destino
    RedirectURI    string        // URI post-verificación
    ClientID       string        // Client ID del origen
    Token          string        // Token de verificación
    TTL            time.Duration // TTL para mostrar en email
}

// SendPasswordResetRequest - Datos para email de reset password
type SendPasswordResetRequest struct {
    TenantSlugOrID string        // UUID o slug del tenant
    UserID         string        // UUID del usuario
    Email          string        // Email destino
    RedirectURI    string        // URI post-reset
    ClientID       string        // Client ID del origen
    Token          string        // Token de reset
    TTL            time.Duration // TTL para mostrar en email
    CustomResetURL string        // URL custom del client (opcional)
}

// SendNotificationRequest - Datos para notificación genérica
type SendNotificationRequest struct {
    TenantSlugOrID string         // UUID o slug del tenant
    Email          string         // Email destino
    TemplateID     string         // "user_blocked", "user_unblocked", etc.
    TemplateVars   map[string]any // Variables para el template
    Subject        string         // Subject override (opcional)
}
```

### Configuración SMTP

```go
type SMTPConfig struct {
    Host      string // Host del servidor SMTP
    Port      int    // Puerto (default 587)
    Username  string // Usuario para autenticación
    Password  string // Password (plain, ya descifrada)
    FromEmail string // Email del remitente
    UseTLS    bool   // Si usar TLS
    TLSMode   string // "auto" | "starttls" | "ssl" | "none"
}
```

### Variables de Template

```go
type VerifyVars struct {
    UserEmail string // {{.UserEmail}}
    Tenant    string // {{.Tenant}}
    Link      string // {{.Link}}
    TTL       string // {{.TTL}}
}

type ResetVars struct {
    UserEmail string // {{.UserEmail}}
    Tenant    string // {{.Tenant}}
    Link      string // {{.Link}}
    TTL       string // {{.TTL}}
}

type BlockedVars struct {
    UserEmail string // {{.UserEmail}}
    Tenant    string // {{.Tenant}}
    Reason    string // {{.Reason}}
    Until     string // {{.Until}}
}

type UnblockedVars struct {
    UserEmail string // {{.UserEmail}}
    Tenant    string // {{.Tenant}}
}
```

---

## Service

### Creación

```go
svc, err := emailv2.NewService(emailv2.ServiceConfig{
    DAL:       dal,                    // store.DataAccessLayer
    MasterKey: os.Getenv("SECRETBOX_MASTER_KEY"),
    BaseURL:   "https://auth.example.com",
    VerifyTTL: 24 * time.Hour,
    ResetTTL:  1 * time.Hour,
    
    // Templates por defecto (opcional, tiene fallback interno)
    DefaultVerifyHTMLTmpl: "...",
    DefaultVerifyTextTmpl: "...",
    DefaultResetHTMLTmpl:  "...",
    DefaultResetTextTmpl:  "...",
})
```

### Métodos

| Método | Descripción |
|--------|-------------|
| `GetSender(ctx, tenantSlugOrID)` | Obtiene Sender configurado para tenant |
| `SendVerificationEmail(ctx, req)` | Envía email de verificación de cuenta |
| `SendPasswordResetEmail(ctx, req)` | Envía email de reset de contraseña |
| `SendNotificationEmail(ctx, req)` | Envía notificación genérica (blocked/unblocked/custom) |
| `TestSMTP(ctx, tenant, email, override)` | Prueba configuración SMTP con email de test |

---

## SenderProvider

Componente interno que resuelve la configuración SMTP de un tenant.

### Flujo

```
1. Resolver tenant (por UUID o slug)
2. Verificar tenant.Settings.SMTP != nil
3. Descifrar password si está encriptada
4. Crear SMTPSender con la configuración
```

### Creación

```go
provider := emailv2.NewSenderProvider(dal, masterKey)
sender, err := provider.GetSender(ctx, "my-tenant")
```

---

## SMTPSender

Implementación de `Sender` usando SMTP.

### Creación

```go
// Opción 1: Constructor directo
sender := emailv2.NewSMTPSender(
    "smtp.example.com",  // host
    587,                 // port
    "noreply@example.com", // from
    "user",              // username
    "password",          // password
)
sender.TLSMode = "starttls"

// Opción 2: Desde SMTPConfig
sender := emailv2.FromConfig(config)
```

### Modos TLS

| Modo | Descripción |
|------|-------------|
| `auto` | go-mail negocia automáticamente (default) |
| `starttls` | STARTTLS obligatorio |
| `ssl` | SSL/TLS directo (puerto 465) |
| `none` | Sin TLS (no recomendado) |

---

## Diagnóstico de Errores

`DiagnoseSMTP(err)` analiza errores SMTP y retorna información útil.

### Códigos de Diagnóstico

| Código | Descripción | Temporal |
|--------|-------------|----------|
| `auth` | Autenticación fallida | ❌ |
| `tls` | Error de TLS/certificado | ❌ |
| `dial` | No se puede conectar al servidor | ✅ |
| `timeout` | Timeout de conexión | ✅ |
| `rate_limited` | Rate limit del servidor | ✅ |
| `invalid_recipient` | Destinatario no existe | ❌ |
| `rejected` | Email rechazado (DMARC/SPF) | ❌ |
| `network` | Error de red genérico | ✅ |
| `unknown` | Error desconocido | ❌ |

### Uso

```go
if err := sender.Send(...); err != nil {
    diag := emailv2.DiagnoseSMTP(err)
    if diag.Temporary {
        // Reintentar más tarde
    }
    log.Error("SMTP error", "code", diag.Code)
}
```

---

## Templates Multi-idioma

El servicio soporta templates por idioma con fallback automático.

### Estructura en tenant.yaml

```yaml
settings:
  mailing:
    templates:
      es:
        verify_email:
          subject: "Verifica tu correo electrónico"
          body: "<!doctype html>..."
        reset_password:
          subject: "Restablecer contraseña"
          body: "..."
      en:
        verify_email:
          subject: "Verify your email"
          body: "..."
```

### Templates Disponibles

| ID | Descripción | Variables |
|----|-------------|-----------|
| `verify_email` | Verificación de cuenta | UserEmail, Tenant, Link, TTL |
| `reset_password` | Reset de contraseña | UserEmail, Tenant, Link, TTL |
| `user_blocked` | Usuario bloqueado | UserEmail, Tenant, Reason, Until |
| `user_unblocked` | Usuario desbloqueado | UserEmail, Tenant |

### Lógica de Fallback

```
1. Buscar template[userLanguage][templateID]
2. Si no existe → template[tenantLanguage][templateID]
3. Si no existe → template["es"][templateID]
4. Si no existe → fallback hardcodeado mínimo
```

### Email de Prueba

```go
// GetTestEmailContent retorna contenido del email de test según idioma
content := emailv2.GetTestEmailContent(tenantName, timestamp, "es")
// content.Subject, content.HTMLBody, content.TextBody
```

---

## Ejemplos de Uso

### Enviar Email de Verificación

```go
err := emailSvc.SendVerificationEmail(ctx, emailv2.SendVerificationRequest{
    TenantSlugOrID: "my-tenant",
    UserID:         userID,
    Email:          "user@example.com",
    Token:          verificationToken,
    ClientID:       "my-app",
    RedirectURI:    "https://app.example.com/verified",
    TTL:            24 * time.Hour,
})
```

### Enviar Notificación de Usuario Bloqueado

```go
err := emailSvc.SendNotificationEmail(ctx, emailv2.SendNotificationRequest{
    TenantSlugOrID: "my-tenant",
    Email:          "user@example.com",
    TemplateID:     "user_blocked",
    TemplateVars: map[string]any{
        "UserEmail": "user@example.com",
        "Tenant":    "My Company",
        "Reason":    "Múltiples intentos fallidos de login",
        "Until":     "24 horas",
    },
})
```

### Probar Configuración SMTP

```go
// Con config del tenant
err := emailSvc.TestSMTP(ctx, "my-tenant", "admin@example.com", nil)

// Con config override
err := emailSvc.TestSMTP(ctx, "my-tenant", "admin@example.com", &emailv2.SMTPConfig{
    Host:      "smtp.gmail.com",
    Port:      587,
    Username:  "test@gmail.com",
    Password:  "app-password",
    FromEmail: "test@gmail.com",
})
```

---

## Errores

```go
var (
    ErrNoSMTPConfig   = errors.New("email: no SMTP config")
    ErrTenantNotFound = errors.New("email: tenant not found")
    ErrTemplateRender = errors.New("email: template render failed")
    ErrSendFailed     = errors.New("email: send failed")
    ErrInvalidInput   = errors.New("email: invalid input")
)
```

---

## Archivos del Paquete

| Archivo | Propósito |
|---------|-----------|
| `doc.go` | Documentación godoc del paquete |
| `interfaces.go` | Interfaces: Sender, SenderProvider, TemplateLoader |
| `types.go` | DTOs: Request structs, SMTPConfig, template vars |
| `service.go` | Implementación principal del Service |
| `sender_provider.go` | SenderProvider con descifrado de passwords |
| `smtp.go` | SMTPSender usando go-mail |
| `diag.go` | Diagnóstico de errores SMTP |
| `test_template.go` | Templates del email de prueba (ES/EN) |
