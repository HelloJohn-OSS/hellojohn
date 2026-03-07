package emailv2

import "time"

// ─── DTOs de Request ───

// SendVerificationRequest contiene los datos para enviar un email de verificación.
type SendVerificationRequest struct {
	TenantSlugOrID string        // Puede ser UUID o slug del tenant
	UserID         string        // UUID del usuario
	Email          string        // Email destino
	RedirectURI    string        // URI de redirección post-verificación
	ClientID       string        // Client ID del origen
	Token          string        // Token de verificación ya generado
	TTL            time.Duration // TTL para mostrar en el email
}

// SendPasswordResetRequest contiene los datos para enviar un email de reset de password.
type SendPasswordResetRequest struct {
	TenantSlugOrID string        // Puede ser UUID o slug del tenant
	UserID         string        // UUID del usuario
	Email          string        // Email destino
	RedirectURI    string        // URI de redirección post-reset
	ClientID       string        // Client ID del origen
	Token          string        // Token de reset ya generado
	TTL            time.Duration // TTL para mostrar en el email
	CustomResetURL string        // URL custom del client (si existe)
}

// SendNotificationRequest contiene los datos para enviar una notificación genérica.
type SendNotificationRequest struct {
	TenantSlugOrID string         // Puede ser UUID o slug del tenant
	Email          string         // Email destino
	TemplateID     string         // ID del template: "user_blocked", "user_unblocked", etc.
	TemplateVars   map[string]any // Variables para el template
	Subject        string         // Subject del email (override del template)
}

// ─── Configuración SMTP ───

// SMTPConfig contiene la configuración para conectarse a un servidor SMTP.
type SMTPConfig struct {
	Host      string // Host del servidor SMTP
	Port      int    // Puerto (default 587)
	Username  string // Usuario para autenticación
	Password  string // Password (plain, ya descifrada)
	FromEmail string // Email del remitente
	UseTLS    bool   // Si usar TLS
	TLSMode   string // "auto" | "starttls" | "ssl" | "none"
}

// ─── Variables de Template ───

// VerifyVars son las variables para el template de verificación.
type VerifyVars struct {
	UserEmail string
	Tenant    string
	Link      string
	TTL       string
}

// ResetVars son las variables para el template de reset password.
type ResetVars struct {
	UserEmail string
	Tenant    string
	Link      string
	TTL       string
}

// BlockedVars son las variables para el template de usuario bloqueado.
type BlockedVars struct {
	UserEmail string
	Tenant    string
	Reason    string
	Until     string
}

// UnblockedVars son las variables para el template de usuario desbloqueado.
type UnblockedVars struct {
	UserEmail string
	Tenant    string
}
