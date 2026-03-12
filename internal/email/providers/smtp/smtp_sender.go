package smtp

import (
	"fmt"

	emailv2 "github.com/dropDatabas3/hellojohn/internal/email"
)

// Build construye un sender SMTP para el registro de providers.
func Build(cfg emailv2.EmailProviderConfig, _ string) (emailv2.Sender, error) {
	smtpCfg := cfg.SMTP
	if smtpCfg == nil {
		return nil, fmt.Errorf("%w: smtp config block required", emailv2.ErrEmailConfig)
	}
	if smtpCfg.Host == "" {
		return nil, fmt.Errorf("%w: smtp host required", emailv2.ErrEmailConfig)
	}

	port := smtpCfg.Port
	if port == 0 {
		port = 587
	}

	from := smtpCfg.FromEmail
	if from == "" {
		from = cfg.FromEmail
	}

	s := emailv2.NewSMTPSender(
		smtpCfg.Host,
		port,
		from,
		smtpCfg.Username,
		smtpCfg.Password,
	)
	if smtpCfg.TLSMode != "" {
		s.TLSMode = smtpCfg.TLSMode
	} else if smtpCfg.UseTLS {
		s.TLSMode = "starttls"
	}

	return s, nil
}
