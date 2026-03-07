package emailv2

import (
	"crypto/tls"
	"fmt"

	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	mail "github.com/go-mail/mail"
)

// SMTPSender implementa Sender usando SMTP.
type SMTPSender struct {
	Host               string
	Port               int
	From               string
	User               string
	Pass               string
	TLSMode            string // "auto" | "starttls" | "ssl" | "none"
	InsecureSkipVerify bool
}

// NewSMTPSender crea un nuevo SMTPSender con los parámetros dados.
func NewSMTPSender(host string, port int, from, user, pass string) *SMTPSender {
	return &SMTPSender{
		Host:    host,
		Port:    port,
		From:    from,
		User:    user,
		Pass:    pass,
		TLSMode: "auto",
	}
}

// FromConfig crea un SMTPSender desde SMTPConfig.
func FromConfig(cfg SMTPConfig) *SMTPSender {
	s := NewSMTPSender(cfg.Host, cfg.Port, cfg.FromEmail, cfg.Username, cfg.Password)
	if cfg.TLSMode != "" {
		s.TLSMode = cfg.TLSMode
	} else if cfg.UseTLS {
		s.TLSMode = "starttls"
	}
	return s
}

// Send envía un email con contenido HTML y texto plano.
func (s *SMTPSender) Send(to, subject, htmlBody, textBody string) error {
	log := logger.L().With(
		logger.String("component", "SMTPSender"),
		logger.String("host", s.Host),
		logger.Int("port", s.Port),
		logger.String("to", to),
	)

	log.Debug("sending email",
		logger.String("from", s.From),
		logger.String("subject", subject),
		logger.String("tls_mode", s.TLSMode),
	)

	m := mail.NewMessage()
	m.SetHeader("From", s.From)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)

	// Preferimos multipart/alternative (txt + html)
	if textBody != "" {
		m.SetBody("text/plain", textBody)
	}
	if htmlBody != "" {
		if textBody == "" {
			m.SetBody("text/html", htmlBody)
		} else {
			m.AddAlternative("text/html", htmlBody)
		}
	}

	d := mail.NewDialer(s.Host, s.Port, s.User, s.Pass)
	d.TLSConfig = &tls.Config{
		ServerName:         s.Host,
		InsecureSkipVerify: s.InsecureSkipVerify, // solo dev
	}

	switch s.TLSMode {
	case "ssl":
		d.SSL = true
	case "none":
		d.TLSConfig = &tls.Config{InsecureSkipVerify: s.InsecureSkipVerify}
	default:
		// "auto"/"starttls": go-mail negocia STARTTLS si corresponde
	}

	if err := d.DialAndSend(m); err != nil {
		log.Error("smtp send failed", logger.Err(err))
		return fmt.Errorf("smtp send: %w", err)
	}

	log.Info("email sent successfully")
	return nil
}
