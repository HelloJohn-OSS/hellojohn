package admin

import (
	"context"
	"fmt"
	"strings"
	"time"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"go.uber.org/zap"
)

// MailingService defines operations for email testing.
type MailingService interface {
	SendTestEmail(ctx context.Context, tenantID, tenantName string, smtpSettings SMTPConfig, req dto.SendTestEmailRequest) (*dto.SendTestEmailResponse, error)
}

// SMTPConfig contains SMTP configuration.
type SMTPConfig struct {
	Host      string
	Port      int
	FromEmail string
	Username  string
	Password  string
	UseTLS    bool
}

// EmailSender sends emails.
type EmailSender interface {
	Send(to, subject, htmlBody, textBody string) error
}

// EmailSenderFactory creates email senders from SMTP config.
type EmailSenderFactory interface {
	NewSender(cfg SMTPConfig) EmailSender
}

type mailingService struct {
	senderFactory EmailSenderFactory
}

// NewMailingService creates a new MailingService.
func NewMailingService(factory EmailSenderFactory) MailingService {
	return &mailingService{
		senderFactory: factory,
	}
}

// Service errors
var (
	ErrMailingMissingTo   = fmt.Errorf("field 'to' is required")
	ErrMailingMissingSMTP = fmt.Errorf("no SMTP configuration available")
	ErrMailingSendFailed  = fmt.Errorf("failed to send email")
)

// SendTestEmail sends a test email using provided or tenant SMTP settings.
func (s *mailingService) SendTestEmail(ctx context.Context, tenantID, tenantName string, smtpSettings SMTPConfig, req dto.SendTestEmailRequest) (*dto.SendTestEmailResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("admin.mailing"),
		logger.Op("SendTestEmail"),
	)

	// Validate input
	to := strings.TrimSpace(req.To)
	if to == "" {
		return nil, ErrMailingMissingTo
	}

	// Determine effective SMTP config
	var cfg SMTPConfig

	if req.SMTPOverride != nil {
		// Use override from request
		cfg = SMTPConfig{
			Host:      req.SMTPOverride.Host,
			Port:      req.SMTPOverride.Port,
			FromEmail: req.SMTPOverride.FromEmail,
			Username:  req.SMTPOverride.Username,
			Password:  req.SMTPOverride.Password,
			UseTLS:    req.SMTPOverride.UseTLS,
		}
	} else {
		// Use tenant SMTP settings
		cfg = smtpSettings
	}

	// Validate SMTP config
	if cfg.Host == "" {
		return nil, ErrMailingMissingSMTP
	}

	// Default port
	if cfg.Port == 0 {
		cfg.Port = 587
	}

	// Create sender
	sender := s.senderFactory.NewSender(cfg)

	// Build email content
	start := time.Now()
	subject := fmt.Sprintf("Mailing Test - %s", tenantName)
	bodyHTML := fmt.Sprintf(`
		<h1>Mailing Configurado Correctamente</h1>
		<p>Hola,</p>
		<p>Este es un correo de prueba enviado desde <strong>%s</strong>.</p>
		<p>Configuración usada:</p>
		<ul>
			<li>Host: %s</li>
			<li>Port: %d</li>
			<li>User: %s</li>
		</ul>
		<p>Enviado en: %s</p>
	`, tenantName, cfg.Host, cfg.Port, cfg.Username, start.Format(time.RFC1123))

	bodyText := fmt.Sprintf("Mailing Configurado Correctamente\n\nEste es un correo de prueba desde %s.\nConfiguración: Host=%s Port=%d User=%s\n",
		tenantName, cfg.Host, cfg.Port, cfg.Username)

	// Send email
	if err := sender.Send(to, subject, bodyHTML, bodyText); err != nil {
		log.Error("test email send failed",
			zap.String("to", to),
			zap.String("host", cfg.Host),
			logger.Err(err),
		)
		return nil, fmt.Errorf("%w: %v", ErrMailingSendFailed, err)
	}

	log.Info("test email sent successfully",
		zap.String("to", to),
		zap.String("host", cfg.Host),
	)

	return &dto.SendTestEmailResponse{
		Status: "ok",
		SentTo: to,
	}, nil
}
