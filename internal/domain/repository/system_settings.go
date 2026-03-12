package repository

import (
	"context"
	"time"
)

// GlobalEmailProviderSettings es la configuracion global del sistema (control plane).
// Se usa como fallback para tenants sin email provider propio.
type GlobalEmailProviderSettings struct {
	Provider  string `json:"provider" yaml:"provider"` // smtp|resend|sendgrid|mailgun
	FromEmail string `json:"fromEmail" yaml:"fromEmail"`
	ReplyTo   string `json:"replyTo,omitempty" yaml:"replyTo,omitempty"`
	TimeoutMs int    `json:"timeoutMs,omitempty" yaml:"timeoutMs,omitempty"`

	APIKeyEnc string `json:"-" yaml:"apiKeyEnc,omitempty"`
	Domain    string `json:"domain,omitempty" yaml:"domain,omitempty"`
	Region    string `json:"region,omitempty" yaml:"region,omitempty"`

	SMTPHost        string `json:"smtpHost,omitempty" yaml:"smtpHost,omitempty"`
	SMTPPort        int    `json:"smtpPort,omitempty" yaml:"smtpPort,omitempty"`
	SMTPUsername    string `json:"smtpUsername,omitempty" yaml:"smtpUsername,omitempty"`
	SMTPPasswordEnc string `json:"-" yaml:"smtpPasswordEnc,omitempty"`
	SMTPUseTLS      bool   `json:"smtpUseTLS,omitempty" yaml:"smtpUseTLS,omitempty"`

	UpdatedAt time.Time `json:"updatedAt,omitempty" yaml:"updatedAt,omitempty"`
	UpdatedBy string    `json:"updatedBy,omitempty" yaml:"updatedBy,omitempty"`
}

// SystemSettingsRepository administra configuracion global del sistema.
type SystemSettingsRepository interface {
	// GetEmailProvider retorna nil,nil cuando no existe configuracion guardada.
	GetEmailProvider(ctx context.Context) (*GlobalEmailProviderSettings, error)
	SetEmailProvider(ctx context.Context, settings GlobalEmailProviderSettings, actor string) error
	DeleteEmailProvider(ctx context.Context) error
}
