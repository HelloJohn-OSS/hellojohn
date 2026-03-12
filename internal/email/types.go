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

// Multi-provider model

// ProviderKind identifica el tipo de proveedor de email.
type ProviderKind string

const (
	ProviderKindSMTP     ProviderKind = "smtp"
	ProviderKindResend   ProviderKind = "resend"
	ProviderKindSendGrid ProviderKind = "sendgrid"
	ProviderKindMailgun  ProviderKind = "mailgun"
)

// EmailProviderConfig es la configuraciÃ³n unificada para enviar email.
type EmailProviderConfig struct {
	Provider  ProviderKind `json:"provider" yaml:"provider"`
	FromEmail string       `json:"fromEmail" yaml:"fromEmail"`
	ReplyTo   string       `json:"replyTo,omitempty" yaml:"replyTo,omitempty"`
	TimeoutMs int          `json:"timeoutMs,omitempty" yaml:"timeoutMs,omitempty"`

	// API providers
	APIKey    string `json:"apiKey,omitempty" yaml:"-"`
	APIKeyEnc string `json:"-" yaml:"apiKeyEnc,omitempty"`
	Domain    string `json:"domain,omitempty" yaml:"domain,omitempty"`
	Region    string `json:"region,omitempty" yaml:"region,omitempty"`

	// SMTP provider
	SMTP *SMTPConfig `json:"smtp,omitempty" yaml:"smtp,omitempty"`
}

// SystemSMTPConfig mantiene compatibilidad con la configuraciÃ³n SMTP heredada.
type SystemSMTPConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	From     string
}

// IsConfigured retorna true cuando el SMTP global tiene mÃ­nimo requerido.
func (c SystemSMTPConfig) IsConfigured() bool {
	return c.Host != "" && c.From != ""
}

// SystemEmailConfig configura el proveedor global del sistema (env fallback).
type SystemEmailConfig struct {
	Provider  string
	FromEmail string
	ReplyTo   string
	TimeoutMs int

	ResendAPIKey   string
	SendGridAPIKey string
	SendGridDomain string
	MailgunAPIKey  string
	MailgunDomain  string
	MailgunRegion  string

	SMTP SystemSMTPConfig
}

// IsConfigured retorna true si hay un provider efectivo.
func (c SystemEmailConfig) IsConfigured() bool {
	return c.Provider != "" || c.SMTP.IsConfigured()
}
