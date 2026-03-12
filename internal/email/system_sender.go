package emailv2

import (
	"bytes"
	"context"
	"fmt"
	htemplate "html/template"
	"regexp"
	"strings"
	ttemplate "text/template"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	sec "github.com/dropDatabas3/hellojohn/internal/security/secretbox"
)

// SystemEmailService envia emails del sistema (no asociados a un tenant).
type SystemEmailService interface {
	SendAdminInvite(ctx context.Context, email, name, inviterName, inviteLink string) error
	SendSystemNotification(ctx context.Context, email, subject, body string) error
	SendPaymentFailed(ctx context.Context, email, name string) error
	SendOnboardCredentials(ctx context.Context, toEmail, appName, claimURL string) error
}

const adminInviteHTMLEN = `<!DOCTYPE html>
<html>
<body>
<p>Hello {{.InviteeName}},</p>
<p>{{.InviterName}} has invited you to join HelloJohn as an administrator.</p>
<p><a href="{{.InviteLink}}">Accept Invitation</a></p>
<p>This invitation expires in {{.ExpiresIn}}.</p>
<p>- {{.ProductName}} Team</p>
</body>
</html>`

const adminInviteTextEN = `Hello {{.InviteeName}},

{{.InviterName}} has invited you to join HelloJohn as an administrator.

Accept your invitation: {{.InviteLink}}

This invitation expires in {{.ExpiresIn}}.

- {{.ProductName}} Team`

const adminInviteHTMLES = `<!DOCTYPE html>
<html>
<body>
<p>Hola {{.InviteeName}},</p>
<p>{{.InviterName}} te invito a unirte a HelloJohn como administrador.</p>
<p><a href="{{.InviteLink}}">Aceptar Invitacion</a></p>
<p>Esta invitacion vence en {{.ExpiresIn}}.</p>
<p>- Equipo de {{.ProductName}}</p>
</body>
</html>`

const adminInviteTextES = `Hola {{.InviteeName}},

{{.InviterName}} te invito a unirte a HelloJohn como administrador.

Acepta tu invitacion: {{.InviteLink}}

Esta invitacion vence en {{.ExpiresIn}}.

- Equipo de {{.ProductName}}`

type adminInviteVars struct {
	InviterName string
	InviteeName string
	InviteLink  string
	ExpiresIn   string
	ProductName string
}

type systemEmailService struct {
	cfg             SystemEmailConfig
	masterKey       string
	systemSettingsR repository.SystemSettingsRepository
}

// NewSystemEmailService mantiene compatibilidad con la firma legacy SMTP-only.
func NewSystemEmailService(cfg SystemSMTPConfig) SystemEmailService {
	newCfg := SystemEmailConfig{}
	if cfg.IsConfigured() {
		newCfg = SystemEmailConfig{
			Provider:  string(ProviderKindSMTP),
			FromEmail: cfg.From,
			SMTP:      cfg,
		}
	}
	return NewSystemEmailServiceWithSources(newCfg, "", nil)
}

// NewSystemEmailServiceWithConfig permite provider global del sistema (solo env).
func NewSystemEmailServiceWithConfig(cfg SystemEmailConfig, masterKey string) SystemEmailService {
	return NewSystemEmailServiceWithSources(cfg, masterKey, nil)
}

// NewSystemEmailServiceWithSources usa:
// 1) Global provider (control plane)
// 2) Env provider
func NewSystemEmailServiceWithSources(cfg SystemEmailConfig, masterKey string, systemSettings repository.SystemSettingsRepository) SystemEmailService {
	return &systemEmailService{
		cfg:             cfg,
		masterKey:       masterKey,
		systemSettingsR: systemSettings,
	}
}

var _ SystemEmailService = (*systemEmailService)(nil)

func (s *systemEmailService) SendAdminInvite(ctx context.Context, email, name, inviterName, inviteLink string) error {
	sender, err := s.getSender(ctx)
	if err != nil {
		return err
	}

	lang := "en"
	vars := adminInviteVars{
		InviterName: inviterName,
		InviteeName: name,
		InviteLink:  inviteLink,
		ExpiresIn:   "7 days",
		ProductName: "HelloJohn",
	}

	htmlBody, textBody, err := s.renderAdminInvite(vars, lang)
	if err != nil {
		return fmt.Errorf("render admin invite: %w", err)
	}

	subject := "You've been invited to HelloJohn"
	if lang == "es" {
		subject = "Te invitaron a HelloJohn"
	}

	return sender.Send(ctx, email, subject, htmlBody, textBody)
}

func (s *systemEmailService) SendSystemNotification(ctx context.Context, email, subject, body string) error {
	sender, err := s.getSender(ctx)
	if err != nil {
		return err
	}
	htmlBody, textBody := renderSystemNotificationEmail(subject, body)
	return sender.Send(ctx, email, subject, htmlBody, textBody)
}

func (s *systemEmailService) SendPaymentFailed(ctx context.Context, email, name string) error {
	sender, err := s.getSender(ctx)
	if err != nil {
		return err
	}
	subject := "Action required: payment failed"
	htmlBody := fmt.Sprintf(`<p>Hi %s,</p><p>Your recent payment for HelloJohn failed. Please update your payment method to avoid service interruption.</p><p><a href="https://panel.hellojohn.io/admin/billing">Manage billing</a></p><p>- HelloJohn Team</p>`, name)
	textBody := fmt.Sprintf("Hi %s,\n\nYour recent payment for HelloJohn failed. Please update your payment method to avoid service interruption.\n\nManage billing: https://panel.hellojohn.io/admin/billing\n\n- HelloJohn Team", name)
	return sender.Send(ctx, email, subject, htmlBody, textBody)
}

func (s *systemEmailService) SendOnboardCredentials(ctx context.Context, toEmail, appName, claimURL string) error {
	sender, err := s.getSender(ctx)
	if err != nil {
		return err
	}
	subject := fmt.Sprintf("Your HelloJohn app '%s' is ready", appName)
	htmlBody := fmt.Sprintf(`<p>Your app <strong>%s</strong> has been created on HelloJohn.</p><p>Claim your tenant to unlock full access:</p><p><a href="%s">Claim your app</a></p><p>This link expires in 30 days.</p><p>- HelloJohn Team</p>`, appName, claimURL)
	textBody := fmt.Sprintf("Your app '%s' has been created on HelloJohn.\n\nClaim your tenant:\n%s\n\nThis link expires in 30 days.\n\n- HelloJohn Team", appName, claimURL)
	return sender.Send(ctx, toEmail, subject, htmlBody, textBody)
}

func (s *systemEmailService) getSender(ctx context.Context) (Sender, error) {
	// 1) Global provider del control plane
	if s.systemSettingsR != nil {
		global, err := s.systemSettingsR.GetEmailProvider(ctx)
		if err == nil && global != nil && strings.TrimSpace(global.Provider) != "" {
			cfg, cfgErr := s.decryptGlobalConfig(*global)
			if cfgErr == nil && cfg.Provider != "" {
				return BuildSenderFromConfig(cfg, s.masterKey)
			}
		}
	}

	// 2) Env provider
	cfg := systemEmailToProviderConfig(s.cfg)
	if cfg.Provider == "" {
		return nil, ErrSystemEmailNotConfigured
	}
	return BuildSenderFromConfig(cfg, s.masterKey)
}

func (s *systemEmailService) decryptGlobalConfig(in repository.GlobalEmailProviderSettings) (EmailProviderConfig, error) {
	cfg := EmailProviderConfig{
		Provider:  ProviderKind(strings.ToLower(strings.TrimSpace(in.Provider))),
		FromEmail: strings.TrimSpace(in.FromEmail),
		ReplyTo:   strings.TrimSpace(in.ReplyTo),
		TimeoutMs: in.TimeoutMs,
		Domain:    strings.TrimSpace(in.Domain),
		Region:    strings.ToLower(strings.TrimSpace(in.Region)),
	}
	if cfg.TimeoutMs <= 0 {
		cfg.TimeoutMs = 10000
	}

	if strings.TrimSpace(in.APIKeyEnc) != "" {
		plain, err := sec.DecryptWithKey(s.masterKey, in.APIKeyEnc)
		if err != nil {
			return EmailProviderConfig{}, fmt.Errorf("%w: decrypt global api key: %v", ErrEmailConfig, err)
		}
		cfg.APIKey = plain
	}

	if strings.EqualFold(in.Provider, string(ProviderKindSMTP)) || strings.TrimSpace(in.SMTPHost) != "" {
		smtpPassword := ""
		if strings.TrimSpace(in.SMTPPasswordEnc) != "" {
			plain, err := sec.DecryptWithKey(s.masterKey, in.SMTPPasswordEnc)
			if err != nil {
				return EmailProviderConfig{}, fmt.Errorf("%w: decrypt global smtp password: %v", ErrEmailConfig, err)
			}
			smtpPassword = plain
		}
		cfg.SMTP = &SMTPConfig{
			Host:      strings.TrimSpace(in.SMTPHost),
			Port:      in.SMTPPort,
			Username:  strings.TrimSpace(in.SMTPUsername),
			Password:  smtpPassword,
			FromEmail: cfg.FromEmail,
			UseTLS:    in.SMTPUseTLS,
		}
	}

	return cfg, nil
}

func (s *systemEmailService) renderAdminInvite(vars adminInviteVars, lang string) (html, text string, err error) {
	var htmlTmplStr, textTmplStr string
	switch lang {
	case "es":
		htmlTmplStr = adminInviteHTMLES
		textTmplStr = adminInviteTextES
	default:
		htmlTmplStr = adminInviteHTMLEN
		textTmplStr = adminInviteTextEN
	}

	var htmlBuf bytes.Buffer
	ht, err := htemplate.New("html").Parse(htmlTmplStr)
	if err != nil {
		return "", "", err
	}
	if err := ht.Execute(&htmlBuf, vars); err != nil {
		return "", "", err
	}

	var textBuf bytes.Buffer
	tt, err := ttemplate.New("text").Parse(textTmplStr)
	if err != nil {
		return "", "", err
	}
	if err := tt.Execute(&textBuf, vars); err != nil {
		return "", "", err
	}

	return htmlBuf.String(), textBuf.String(), nil
}

var urlPattern = regexp.MustCompile(`https?://[^\s]+`)

func renderSystemNotificationEmail(subject, body string) (htmlBody, textBody string) {
	normalizedBody := strings.TrimSpace(body)
	if normalizedBody == "" {
		normalizedBody = "You have a new notification from HelloJohn."
	}

	ctaURL := urlPattern.FindString(normalizedBody)
	cleanBody := strings.TrimSpace(urlPattern.ReplaceAllString(normalizedBody, ""))
	if cleanBody == "" {
		cleanBody = normalizedBody
	}

	paragraphs := make([]string, 0, 3)
	for _, p := range strings.Split(cleanBody, "\n\n") {
		p = strings.TrimSpace(p)
		if p != "" {
			paragraphs = append(paragraphs, htemplate.HTMLEscapeString(p))
		}
	}
	if len(paragraphs) == 0 {
		paragraphs = append(paragraphs, htemplate.HTMLEscapeString(cleanBody))
	}

	ctaHTML := ""
	if ctaURL != "" {
		ctaHTML = fmt.Sprintf(
			`<table role="presentation" cellpadding="0" cellspacing="0" style="margin:20px 0 0 0;"><tr><td style="border-radius:10px;background:linear-gradient(135deg,#4f46e5 0%%,#2563eb 100%%);"><a href="%s" style="display:inline-block;padding:12px 20px;font-size:14px;font-weight:600;color:#ffffff;text-decoration:none;">Open link</a></td></tr></table>`,
			htemplate.HTMLEscapeString(ctaURL),
		)
	}

	contentHTML := ""
	for _, p := range paragraphs {
		contentHTML += fmt.Sprintf(`<p style="margin:0 0 12px 0;font-size:15px;line-height:1.65;color:#334155;">%s</p>`, p)
	}

	subjectEscaped := htemplate.HTMLEscapeString(subject)
	htmlBody = fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
  <body style="margin:0;padding:0;background:#f6f8fc;font-family:Inter,Segoe UI,Arial,sans-serif;color:#0f172a;">
    <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background:#f6f8fc;padding:28px 12px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="max-width:620px;background:#ffffff;border:1px solid #e5e7eb;border-radius:14px;overflow:hidden;">
            <tr>
              <td style="padding:22px 26px;background:linear-gradient(135deg,#0f172a 0%%,#1e3a8a 55%%,#6d28d9 100%%);color:#ffffff;">
                <div style="font-size:20px;font-weight:700;letter-spacing:-0.02em;">HelloJohn</div>
                <div style="margin-top:6px;font-size:13px;opacity:0.88;">System Notification</div>
              </td>
            </tr>
            <tr>
              <td style="padding:26px;">
                <h2 style="margin:0 0 14px 0;font-size:22px;line-height:1.3;color:#0f172a;">%s</h2>
                %s
                %s
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>`, subjectEscaped, contentHTML, ctaHTML)

	textBody = normalizedBody
	return htmlBody, textBody
}
