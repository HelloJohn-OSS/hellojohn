package emailv2

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	sec "github.com/dropDatabas3/hellojohn/internal/security/secretbox"
	"github.com/dropDatabas3/hellojohn/internal/store"
	"github.com/google/uuid"
)

// SenderBuilder construye un sender a partir de una configuraciÃ³n unificada.
type SenderBuilder func(cfg EmailProviderConfig, masterKey string) (Sender, error)

// SenderFactory implementa SenderProvider con fallback de 5 niveles:
// tenant.emailProvider > tenant.smtp > globalProvider > env > ErrNoEmailConfigured.
type SenderFactory struct {
	dal             store.DataAccessLayer
	systemSettingsR repository.SystemSettingsRepository
	masterKey       string
	envCfg          EmailProviderConfig
	registry        map[ProviderKind]SenderBuilder
}

// NewSenderFactory construye un SenderFactory.
func NewSenderFactory(
	dal store.DataAccessLayer,
	masterKey string,
	systemEmail SystemEmailConfig,
	systemSettings repository.SystemSettingsRepository,
) *SenderFactory {
	return &SenderFactory{
		dal:             dal,
		systemSettingsR: systemSettings,
		masterKey:       masterKey,
		envCfg:          systemEmailToProviderConfig(systemEmail),
		registry:        defaultSenderRegistry(),
	}
}

var (
	senderRegistryMu sync.RWMutex
	senderRegistry   = map[ProviderKind]SenderBuilder{
		ProviderKindSMTP:     buildSMTPSender,
		ProviderKindResend:   missingProviderBuilder(ProviderKindResend),
		ProviderKindSendGrid: missingProviderBuilder(ProviderKindSendGrid),
		ProviderKindMailgun:  missingProviderBuilder(ProviderKindMailgun),
	}
)

// RegisterSenderBuilder permite registrar providers externos (resend/sendgrid/mailgun)
// sin crear ciclos de import con el paquete email.
func RegisterSenderBuilder(kind ProviderKind, builder SenderBuilder) {
	provider := ProviderKind(strings.ToLower(strings.TrimSpace(string(kind))))
	if provider == "" || builder == nil {
		return
	}
	senderRegistryMu.Lock()
	senderRegistry[provider] = builder
	senderRegistryMu.Unlock()
}

func missingProviderBuilder(provider ProviderKind) SenderBuilder {
	return func(cfg EmailProviderConfig, masterKey string) (Sender, error) {
		return nil, fmt.Errorf("%w: provider %q is not registered", ErrEmailConfig, provider)
	}
}

func defaultSenderRegistry() map[ProviderKind]SenderBuilder {
	senderRegistryMu.RLock()
	defer senderRegistryMu.RUnlock()

	out := make(map[ProviderKind]SenderBuilder, len(senderRegistry))
	for kind, builder := range senderRegistry {
		out[kind] = builder
	}
	return out
}

// GetSender resuelve y construye el sender efectivo para el tenant.
func (f *SenderFactory) GetSender(ctx context.Context, tenantSlugOrID string) (Sender, error) {
	tenant, err := f.resolveTenant(ctx, tenantSlugOrID)
	if err != nil {
		return nil, err
	}

	cfg, err := f.resolveConfig(ctx, tenant)
	if err != nil {
		return nil, err
	}
	return f.build(cfg)
}

func (f *SenderFactory) resolveTenant(ctx context.Context, tenantSlugOrID string) (*repository.Tenant, error) {
	tenants := f.dal.ConfigAccess().Tenants()

	if id, err := uuid.Parse(tenantSlugOrID); err == nil {
		if t, getErr := tenants.GetByID(ctx, id.String()); getErr == nil {
			return t, nil
		}
	}

	t, err := tenants.GetBySlug(ctx, tenantSlugOrID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrTenantNotFound, tenantSlugOrID)
	}
	return t, nil
}

func (f *SenderFactory) resolveConfig(ctx context.Context, t *repository.Tenant) (EmailProviderConfig, error) {
	// 1) tenant.emailProvider
	if t.Settings.EmailProvider != nil {
		cfg, err := f.decryptProviderConfig(*t.Settings.EmailProvider)
		if err != nil {
			return EmailProviderConfig{}, err
		}
		if cfg.Provider != "" {
			return cfg, nil
		}
	}

	// 2) tenant.smtp (legacy)
	if t.Settings.SMTP != nil && strings.TrimSpace(t.Settings.SMTP.Host) != "" {
		return legacySMTPtoConfig(t.Settings.SMTP), nil
	}

	// 3) global provider (control plane)
	if f.systemSettingsR != nil {
		global, err := f.systemSettingsR.GetEmailProvider(ctx)
		if err == nil && global != nil && strings.TrimSpace(global.Provider) != "" {
			cfg, decErr := f.decryptGlobalConfig(*global)
			if decErr == nil && cfg.Provider != "" {
				return cfg, nil
			}
		}
	}

	// 4) env provider
	if f.envCfg.Provider != "" {
		return f.envCfg, nil
	}

	// 5) explicit error
	return EmailProviderConfig{}, ErrNoEmailConfigured
}

func (f *SenderFactory) build(cfg EmailProviderConfig) (Sender, error) {
	provider := cfg.Provider
	if provider == "" && cfg.SMTP != nil {
		provider = ProviderKindSMTP
	}

	builder, ok := f.registry[provider]
	if !ok {
		return nil, fmt.Errorf("%w: unknown provider %q", ErrEmailConfig, provider)
	}
	sender, err := builder(cfg, f.masterKey)
	if err != nil {
		return nil, err
	}
	if sender == nil {
		return nil, fmt.Errorf("%w: nil sender for provider %q", ErrEmailConfig, provider)
	}
	return wrapResilientSender(provider, sender), nil
}

// BuildSenderFromConfig construye un sender directo desde una configuracion ya resuelta.
// Se usa para tests de mailing con override y para system email provider global.
func BuildSenderFromConfig(cfg EmailProviderConfig, masterKey string) (Sender, error) {
	provider := cfg.Provider
	if provider == "" && cfg.SMTP != nil {
		provider = ProviderKindSMTP
	}

	registry := defaultSenderRegistry()
	builder, ok := registry[provider]
	if !ok {
		return nil, fmt.Errorf("%w: unknown provider %q", ErrEmailConfig, provider)
	}
	sender, err := builder(cfg, masterKey)
	if err != nil {
		return nil, err
	}
	if sender == nil {
		return nil, fmt.Errorf("%w: nil sender for provider %q", ErrEmailConfig, provider)
	}
	return wrapResilientSender(provider, sender), nil
}

func (f *SenderFactory) decryptProviderConfig(in repository.EmailProviderSettings) (EmailProviderConfig, error) {
	cfg := EmailProviderConfig{
		Provider:  ProviderKind(strings.ToLower(strings.TrimSpace(in.Provider))),
		FromEmail: in.FromEmail,
		ReplyTo:   in.ReplyTo,
		TimeoutMs: in.TimeoutMs,
		Domain:    in.Domain,
		Region:    strings.ToLower(strings.TrimSpace(in.Region)),
	}

	if in.APIKeyEnc != "" {
		plain, err := f.decryptSecret(in.APIKeyEnc)
		if err != nil {
			return EmailProviderConfig{}, err
		}
		cfg.APIKey = plain
	}

	// SMTP block (provider=smtp)
	if strings.EqualFold(in.Provider, string(ProviderKindSMTP)) || in.SMTPHost != "" {
		smtpPassword := ""
		if in.SMTPPasswordEnc != "" {
			plain, err := f.decryptSecret(in.SMTPPasswordEnc)
			if err != nil {
				return EmailProviderConfig{}, err
			}
			smtpPassword = plain
		}
		cfg.SMTP = &SMTPConfig{
			Host:      in.SMTPHost,
			Port:      in.SMTPPort,
			Username:  in.SMTPUsername,
			Password:  smtpPassword,
			FromEmail: in.FromEmail,
			UseTLS:    in.SMTPUseTLS,
		}
	}

	return cfg, nil
}

func (f *SenderFactory) decryptGlobalConfig(in repository.GlobalEmailProviderSettings) (EmailProviderConfig, error) {
	cfg := EmailProviderConfig{
		Provider:  ProviderKind(strings.ToLower(strings.TrimSpace(in.Provider))),
		FromEmail: in.FromEmail,
		ReplyTo:   in.ReplyTo,
		TimeoutMs: in.TimeoutMs,
		Domain:    in.Domain,
		Region:    strings.ToLower(strings.TrimSpace(in.Region)),
	}

	if in.APIKeyEnc != "" {
		plain, err := f.decryptSecret(in.APIKeyEnc)
		if err != nil {
			return EmailProviderConfig{}, err
		}
		cfg.APIKey = plain
	}

	if strings.EqualFold(in.Provider, string(ProviderKindSMTP)) || in.SMTPHost != "" {
		smtpPassword := ""
		if in.SMTPPasswordEnc != "" {
			plain, err := f.decryptSecret(in.SMTPPasswordEnc)
			if err != nil {
				return EmailProviderConfig{}, err
			}
			smtpPassword = plain
		}
		cfg.SMTP = &SMTPConfig{
			Host:      in.SMTPHost,
			Port:      in.SMTPPort,
			Username:  in.SMTPUsername,
			Password:  smtpPassword,
			FromEmail: in.FromEmail,
			UseTLS:    in.SMTPUseTLS,
		}
	}

	return cfg, nil
}

func (f *SenderFactory) decryptSecret(enc string) (string, error) {
	plain, err := sec.DecryptWithKey(f.masterKey, enc)
	if err != nil {
		return "", fmt.Errorf("%w: decrypt provider secret: %v", ErrEmailConfig, err)
	}
	return plain, nil
}

func legacySMTPtoConfig(s *repository.SMTPSettings) EmailProviderConfig {
	from := strings.TrimSpace(s.FromEmail)
	if from == "" {
		from = strings.TrimSpace(s.Username)
	}
	return EmailProviderConfig{
		Provider:  ProviderKindSMTP,
		FromEmail: from,
		SMTP: &SMTPConfig{
			Host:      s.Host,
			Port:      s.Port,
			Username:  s.Username,
			Password:  s.Password,
			FromEmail: from,
			UseTLS:    s.UseTLS,
		},
	}
}

func systemEmailToProviderConfig(c SystemEmailConfig) EmailProviderConfig {
	provider := strings.ToLower(strings.TrimSpace(c.Provider))
	if provider == "" && c.SMTP.IsConfigured() {
		provider = string(ProviderKindSMTP)
	}

	if provider == "" {
		return EmailProviderConfig{}
	}

	timeout := c.TimeoutMs
	if timeout <= 0 {
		timeout = 10000
	}

	switch ProviderKind(provider) {
	case ProviderKindSMTP:
		smtpFrom := c.SMTP.From
		if smtpFrom == "" {
			smtpFrom = c.FromEmail
		}
		return EmailProviderConfig{
			Provider:  ProviderKindSMTP,
			FromEmail: smtpFrom,
			ReplyTo:   c.ReplyTo,
			SMTP: &SMTPConfig{
				Host:      c.SMTP.Host,
				Port:      c.SMTP.Port,
				Username:  c.SMTP.User,
				Password:  c.SMTP.Password,
				FromEmail: smtpFrom,
				UseTLS:    true,
			},
		}
	case ProviderKindResend:
		return EmailProviderConfig{
			Provider:  ProviderKindResend,
			FromEmail: c.FromEmail,
			ReplyTo:   c.ReplyTo,
			TimeoutMs: timeout,
			APIKey:    c.ResendAPIKey,
		}
	case ProviderKindSendGrid:
		return EmailProviderConfig{
			Provider:  ProviderKindSendGrid,
			FromEmail: c.FromEmail,
			ReplyTo:   c.ReplyTo,
			TimeoutMs: timeout,
			APIKey:    c.SendGridAPIKey,
			Domain:    c.SendGridDomain,
		}
	case ProviderKindMailgun:
		region := strings.ToLower(strings.TrimSpace(c.MailgunRegion))
		if region == "" {
			region = "us"
		}
		return EmailProviderConfig{
			Provider:  ProviderKindMailgun,
			FromEmail: c.FromEmail,
			ReplyTo:   c.ReplyTo,
			TimeoutMs: timeout,
			APIKey:    c.MailgunAPIKey,
			Domain:    c.MailgunDomain,
			Region:    region,
		}
	default:
		return EmailProviderConfig{}
	}
}

func buildSMTPSender(cfg EmailProviderConfig, _ string) (Sender, error) {
	smtpCfg := cfg.SMTP
	if smtpCfg == nil {
		return nil, fmt.Errorf("%w: smtp config block required", ErrEmailConfig)
	}
	if smtpCfg.Host == "" {
		return nil, fmt.Errorf("%w: smtp host required", ErrEmailConfig)
	}

	port := smtpCfg.Port
	if port == 0 {
		port = 587
	}

	from := smtpCfg.FromEmail
	if from == "" {
		from = cfg.FromEmail
	}

	s := NewSMTPSender(
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
