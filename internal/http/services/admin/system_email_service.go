package admin

import (
	"context"
	"fmt"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	emailv2 "github.com/dropDatabas3/hellojohn/internal/email"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	"github.com/dropDatabas3/hellojohn/internal/security/secretbox"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

const (
	systemEmailUpdatedEvent audit.EventType = "admin.system_email_provider_updated"
	systemEmailDeletedEvent audit.EventType = "admin.system_email_provider_deleted"
)

// SystemEmailService manages the global email provider for the control plane.
type SystemEmailService interface {
	Get(ctx context.Context) (*dto.SystemEmailGetResponse, error)
	Set(ctx context.Context, req dto.SystemEmailProviderRequest, actor string) (*dto.SystemEmailProviderResponse, error)
	Delete(ctx context.Context, actor string) error
	Test(ctx context.Context, req dto.SystemEmailTestRequest) (*dto.SystemEmailTestResponse, error)
}

type systemEmailService struct {
	dal       store.DataAccessLayer
	masterKey string
	envCfg    emailv2.SystemEmailConfig
	auditBus  *audit.AuditBus
}

// NewSystemEmailService creates the admin service for /v2/admin/system/email.
func NewSystemEmailService(dal store.DataAccessLayer, masterKey string, envCfg emailv2.SystemEmailConfig, auditBus *audit.AuditBus) SystemEmailService {
	return &systemEmailService{
		dal:       dal,
		masterKey: masterKey,
		envCfg:    envCfg,
		auditBus:  auditBus,
	}
}

func (s *systemEmailService) Get(ctx context.Context) (*dto.SystemEmailGetResponse, error) {
	repo := s.repo()
	if repo == nil {
		return &dto.SystemEmailGetResponse{
			EffectiveSource: s.effectiveSourceWithoutControlPlane(),
		}, nil
	}

	current, err := repo.GetEmailProvider(ctx)
	if err != nil {
		return nil, err
	}
	if current != nil && strings.TrimSpace(current.Provider) != "" {
		return &dto.SystemEmailGetResponse{
			EmailProvider:   mapSystemEmailResponse(*current),
			EffectiveSource: "control_plane",
		}, nil
	}

	return &dto.SystemEmailGetResponse{
		EffectiveSource: s.effectiveSourceWithoutControlPlane(),
	}, nil
}

func (s *systemEmailService) Set(ctx context.Context, req dto.SystemEmailProviderRequest, actor string) (*dto.SystemEmailProviderResponse, error) {
	repo := s.repo()
	if repo == nil {
		return nil, fmt.Errorf("system settings repository not available")
	}

	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	if !isValidEmailProvider(provider) {
		return nil, fmt.Errorf("invalid provider %q", req.Provider)
	}
	if strings.TrimSpace(req.FromEmail) == "" {
		return nil, fmt.Errorf("fromEmail is required")
	}

	current, err := repo.GetEmailProvider(ctx)
	if err != nil {
		return nil, err
	}

	settings := repository.GlobalEmailProviderSettings{
		Provider:     provider,
		FromEmail:    strings.TrimSpace(req.FromEmail),
		ReplyTo:      strings.TrimSpace(req.ReplyTo),
		TimeoutMs:    req.TimeoutMs,
		Domain:       strings.TrimSpace(req.Domain),
		Region:       strings.ToLower(strings.TrimSpace(req.Region)),
		SMTPHost:     strings.TrimSpace(req.SMTPHost),
		SMTPPort:     req.SMTPPort,
		SMTPUsername: strings.TrimSpace(req.SMTPUsername),
		SMTPUseTLS:   req.SMTPUseTLS,
	}
	if settings.TimeoutMs <= 0 {
		settings.TimeoutMs = 10000
	}

	if current != nil {
		settings.APIKeyEnc = current.APIKeyEnc
		settings.SMTPPasswordEnc = current.SMTPPasswordEnc
	}

	if strings.TrimSpace(req.APIKey) != "" {
		enc, err := secretbox.Encrypt(req.APIKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt apiKey: %w", err)
		}
		settings.APIKeyEnc = enc
	}
	if strings.TrimSpace(req.SMTPPassword) != "" {
		enc, err := secretbox.Encrypt(req.SMTPPassword)
		if err != nil {
			return nil, fmt.Errorf("encrypt smtpPassword: %w", err)
		}
		settings.SMTPPasswordEnc = enc
	}

	if provider == string(emailv2.ProviderKindSMTP) {
		if settings.SMTPHost == "" {
			return nil, fmt.Errorf("smtpHost is required for smtp provider")
		}
		if settings.SMTPPort <= 0 {
			settings.SMTPPort = 587
		}
		if strings.TrimSpace(settings.SMTPPasswordEnc) == "" {
			return nil, fmt.Errorf("smtpPassword is required for smtp provider")
		}
		settings.APIKeyEnc = ""
		settings.Domain = ""
		settings.Region = ""
	} else {
		settings.SMTPHost = ""
		settings.SMTPPort = 0
		settings.SMTPUsername = ""
		settings.SMTPPasswordEnc = ""
		settings.SMTPUseTLS = false
		if strings.TrimSpace(settings.APIKeyEnc) == "" {
			return nil, fmt.Errorf("apiKey is required for provider %s", provider)
		}
		if provider == string(emailv2.ProviderKindMailgun) {
			if settings.Domain == "" {
				return nil, fmt.Errorf("domain is required for mailgun")
			}
			if settings.Region == "" {
				settings.Region = "us"
			}
		}
	}

	if strings.TrimSpace(actor) == "" {
		actor = "system"
	}
	if err := repo.SetEmailProvider(ctx, settings, actor); err != nil {
		return nil, err
	}

	s.emitAudit(ctx, systemEmailUpdatedEvent, audit.ResultSuccess, map[string]any{
		"provider": provider,
	})

	updated, err := repo.GetEmailProvider(ctx)
	if err != nil {
		return nil, err
	}
	if updated == nil {
		return nil, fmt.Errorf("system email provider was not persisted")
	}
	return mapSystemEmailResponse(*updated), nil
}

func (s *systemEmailService) Delete(ctx context.Context, actor string) error {
	repo := s.repo()
	if repo == nil {
		return fmt.Errorf("system settings repository not available")
	}
	if err := repo.DeleteEmailProvider(ctx); err != nil {
		return err
	}
	s.emitAudit(ctx, systemEmailDeletedEvent, audit.ResultSuccess, map[string]any{
		"actor": actor,
	})
	return nil
}

func (s *systemEmailService) Test(ctx context.Context, req dto.SystemEmailTestRequest) (*dto.SystemEmailTestResponse, error) {
	to := strings.TrimSpace(req.To)
	if to == "" {
		return nil, fmt.Errorf("to is required")
	}

	cfg, err := s.resolveTestConfig(ctx, req.Provider)
	if err != nil {
		return nil, err
	}

	sender, err := emailv2.BuildSenderFromConfig(cfg, s.masterKey)
	if err != nil {
		return nil, err
	}

	subject := "HelloJohn system email test"
	htmlBody := "<p>This is a test email from the global provider configuration.</p>"
	textBody := "This is a test email from the global provider configuration."
	if err := sender.Send(ctx, to, subject, htmlBody, textBody); err != nil {
		return nil, err
	}

	return &dto.SystemEmailTestResponse{
		Success:  true,
		Provider: string(cfg.Provider),
	}, nil
}

func (s *systemEmailService) resolveTestConfig(ctx context.Context, override *dto.SystemEmailProviderRequest) (emailv2.EmailProviderConfig, error) {
	if override != nil {
		return mapSystemEmailOverrideToConfig(*override)
	}

	repo := s.repo()
	if repo != nil {
		current, err := repo.GetEmailProvider(ctx)
		if err != nil {
			return emailv2.EmailProviderConfig{}, err
		}
		if current != nil && strings.TrimSpace(current.Provider) != "" {
			return s.decryptSystemSettings(*current)
		}
	}

	cfg := mapEnvSystemEmailToProvider(s.envCfg)
	if cfg.Provider != "" {
		return cfg, nil
	}

	return emailv2.EmailProviderConfig{}, emailv2.ErrSystemEmailNotConfigured
}

func (s *systemEmailService) decryptSystemSettings(in repository.GlobalEmailProviderSettings) (emailv2.EmailProviderConfig, error) {
	out := emailv2.EmailProviderConfig{
		Provider:  emailv2.ProviderKind(strings.ToLower(strings.TrimSpace(in.Provider))),
		FromEmail: strings.TrimSpace(in.FromEmail),
		ReplyTo:   strings.TrimSpace(in.ReplyTo),
		TimeoutMs: in.TimeoutMs,
		Domain:    strings.TrimSpace(in.Domain),
		Region:    strings.ToLower(strings.TrimSpace(in.Region)),
	}
	if out.TimeoutMs <= 0 {
		out.TimeoutMs = 10000
	}

	if strings.TrimSpace(in.APIKeyEnc) != "" {
		plain, err := secretbox.DecryptWithKey(s.masterKey, in.APIKeyEnc)
		if err != nil {
			return emailv2.EmailProviderConfig{}, fmt.Errorf("decrypt apiKeyEnc: %w", err)
		}
		out.APIKey = plain
	}

	if out.Provider == emailv2.ProviderKindSMTP || strings.TrimSpace(in.SMTPHost) != "" {
		smtpPassword := ""
		if strings.TrimSpace(in.SMTPPasswordEnc) != "" {
			plain, err := secretbox.DecryptWithKey(s.masterKey, in.SMTPPasswordEnc)
			if err != nil {
				return emailv2.EmailProviderConfig{}, fmt.Errorf("decrypt smtpPasswordEnc: %w", err)
			}
			smtpPassword = plain
		}
		out.SMTP = &emailv2.SMTPConfig{
			Host:      strings.TrimSpace(in.SMTPHost),
			Port:      in.SMTPPort,
			Username:  strings.TrimSpace(in.SMTPUsername),
			Password:  smtpPassword,
			FromEmail: out.FromEmail,
			UseTLS:    in.SMTPUseTLS,
		}
	}

	return out, nil
}

func mapSystemEmailOverrideToConfig(req dto.SystemEmailProviderRequest) (emailv2.EmailProviderConfig, error) {
	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	if !isValidEmailProvider(provider) {
		return emailv2.EmailProviderConfig{}, fmt.Errorf("invalid provider %q", req.Provider)
	}
	if strings.TrimSpace(req.FromEmail) == "" {
		return emailv2.EmailProviderConfig{}, fmt.Errorf("fromEmail is required")
	}

	cfg := emailv2.EmailProviderConfig{
		Provider:  emailv2.ProviderKind(provider),
		FromEmail: strings.TrimSpace(req.FromEmail),
		ReplyTo:   strings.TrimSpace(req.ReplyTo),
		TimeoutMs: req.TimeoutMs,
		APIKey:    strings.TrimSpace(req.APIKey),
		Domain:    strings.TrimSpace(req.Domain),
		Region:    strings.ToLower(strings.TrimSpace(req.Region)),
	}
	if cfg.TimeoutMs <= 0 {
		cfg.TimeoutMs = 10000
	}

	if cfg.Provider == emailv2.ProviderKindSMTP {
		if strings.TrimSpace(req.SMTPHost) == "" {
			return emailv2.EmailProviderConfig{}, fmt.Errorf("smtpHost is required for smtp provider")
		}
		port := req.SMTPPort
		if port <= 0 {
			port = 587
		}
		cfg.SMTP = &emailv2.SMTPConfig{
			Host:      strings.TrimSpace(req.SMTPHost),
			Port:      port,
			Username:  strings.TrimSpace(req.SMTPUsername),
			Password:  req.SMTPPassword,
			FromEmail: cfg.FromEmail,
			UseTLS:    req.SMTPUseTLS,
		}
		return cfg, nil
	}

	if cfg.APIKey == "" {
		return emailv2.EmailProviderConfig{}, fmt.Errorf("apiKey is required for provider %s", provider)
	}
	if cfg.Provider == emailv2.ProviderKindMailgun && cfg.Domain == "" {
		return emailv2.EmailProviderConfig{}, fmt.Errorf("domain is required for mailgun")
	}
	if cfg.Provider == emailv2.ProviderKindMailgun && cfg.Region == "" {
		cfg.Region = "us"
	}

	return cfg, nil
}

func mapEnvSystemEmailToProvider(cfg emailv2.SystemEmailConfig) emailv2.EmailProviderConfig {
	provider := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if provider == "" && cfg.SMTP.IsConfigured() {
		provider = string(emailv2.ProviderKindSMTP)
	}
	if provider == "" {
		return emailv2.EmailProviderConfig{}
	}

	timeout := cfg.TimeoutMs
	if timeout <= 0 {
		timeout = 10000
	}

	switch emailv2.ProviderKind(provider) {
	case emailv2.ProviderKindSMTP:
		from := cfg.SMTP.From
		if strings.TrimSpace(from) == "" {
			from = cfg.FromEmail
		}
		return emailv2.EmailProviderConfig{
			Provider:  emailv2.ProviderKindSMTP,
			FromEmail: from,
			ReplyTo:   cfg.ReplyTo,
			SMTP: &emailv2.SMTPConfig{
				Host:      cfg.SMTP.Host,
				Port:      cfg.SMTP.Port,
				Username:  cfg.SMTP.User,
				Password:  cfg.SMTP.Password,
				FromEmail: from,
				UseTLS:    true,
			},
		}
	case emailv2.ProviderKindResend:
		return emailv2.EmailProviderConfig{
			Provider:  emailv2.ProviderKindResend,
			FromEmail: cfg.FromEmail,
			ReplyTo:   cfg.ReplyTo,
			TimeoutMs: timeout,
			APIKey:    cfg.ResendAPIKey,
		}
	case emailv2.ProviderKindSendGrid:
		return emailv2.EmailProviderConfig{
			Provider:  emailv2.ProviderKindSendGrid,
			FromEmail: cfg.FromEmail,
			ReplyTo:   cfg.ReplyTo,
			TimeoutMs: timeout,
			APIKey:    cfg.SendGridAPIKey,
			Domain:    cfg.SendGridDomain,
		}
	case emailv2.ProviderKindMailgun:
		region := strings.ToLower(strings.TrimSpace(cfg.MailgunRegion))
		if region == "" {
			region = "us"
		}
		return emailv2.EmailProviderConfig{
			Provider:  emailv2.ProviderKindMailgun,
			FromEmail: cfg.FromEmail,
			ReplyTo:   cfg.ReplyTo,
			TimeoutMs: timeout,
			APIKey:    cfg.MailgunAPIKey,
			Domain:    cfg.MailgunDomain,
			Region:    region,
		}
	default:
		return emailv2.EmailProviderConfig{}
	}
}

func mapSystemEmailResponse(in repository.GlobalEmailProviderSettings) *dto.SystemEmailProviderResponse {
	if strings.TrimSpace(in.Provider) == "" {
		return nil
	}
	return &dto.SystemEmailProviderResponse{
		Provider:         in.Provider,
		FromEmail:        in.FromEmail,
		ReplyTo:          in.ReplyTo,
		TimeoutMs:        in.TimeoutMs,
		Domain:           in.Domain,
		Region:           in.Region,
		SMTPHost:         in.SMTPHost,
		SMTPPort:         in.SMTPPort,
		SMTPUsername:     in.SMTPUsername,
		SMTPUseTLS:       in.SMTPUseTLS,
		APIKeyConfigured: hasSystemSecretConfigured(in),
		UpdatedAt:        in.UpdatedAt,
		UpdatedBy:        in.UpdatedBy,
	}
}

func hasSystemSecretConfigured(in repository.GlobalEmailProviderSettings) bool {
	if strings.EqualFold(in.Provider, string(emailv2.ProviderKindSMTP)) {
		return strings.TrimSpace(in.SMTPPasswordEnc) != ""
	}
	return strings.TrimSpace(in.APIKeyEnc) != ""
}

func isValidEmailProvider(provider string) bool {
	switch provider {
	case string(emailv2.ProviderKindSMTP),
		string(emailv2.ProviderKindResend),
		string(emailv2.ProviderKindSendGrid),
		string(emailv2.ProviderKindMailgun):
		return true
	default:
		return false
	}
}

func (s *systemEmailService) effectiveSourceWithoutControlPlane() string {
	if s.envCfg.IsConfigured() {
		return "env"
	}
	return "none"
}

func (s *systemEmailService) repo() repository.SystemSettingsRepository {
	if s.dal == nil || s.dal.ConfigAccess() == nil {
		return nil
	}
	return s.dal.ConfigAccess().SystemSettings()
}

func (s *systemEmailService) emitAudit(ctx context.Context, eventType audit.EventType, result string, meta map[string]any) {
	if s.auditBus == nil {
		return
	}

	actorID := "system"
	if claims := mw.GetAdminClaims(ctx); claims != nil {
		if strings.TrimSpace(claims.Email) != "" {
			actorID = claims.Email
		} else if strings.TrimSpace(claims.AdminID) != "" {
			actorID = claims.AdminID
		}
	}

	evt := audit.NewEvent(eventType, audit.ControlPlaneTenantID).
		WithActor(actorID, audit.ActorAdmin).
		WithTarget("email_provider", audit.TargetTenant).
		WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx)).
		WithResult(result)

	for k, v := range meta {
		evt = evt.WithMeta(k, v)
	}

	s.auditBus.Emit(evt)
}
