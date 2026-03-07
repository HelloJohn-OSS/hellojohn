package emailv2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	htemplate "html/template"
	ttemplate "text/template"
)

// ─── Error ───

var ErrSystemSMTPNotConfigured = errors.New("system email: SMTP not configured")

// ─── Interface ───

// SystemEmailService envía emails del sistema (no asociados a un tenant).
// Usa el SMTP global configurado en SystemSMTPConfig.
type SystemEmailService interface {
	// SendAdminInvite envía un email de invitación a un nuevo admin.
	SendAdminInvite(ctx context.Context, email, name, inviterName, inviteLink string) error
	// SendSystemNotification envía una notificación genérica del sistema.
	SendSystemNotification(ctx context.Context, email, subject, body string) error
	// SendPaymentFailed notifica al admin que su pago falló.
	SendPaymentFailed(ctx context.Context, email, name string) error
	// SendOnboardCredentials envía las credenciales de una app recién creada vía Instant Onboard.
	SendOnboardCredentials(ctx context.Context, toEmail, appName, claimURL string) error
}

// ─── Templates ───

const adminInviteHTMLEN = `<!DOCTYPE html>
<html>
<body>
<p>Hello {{.InviteeName}},</p>
<p>{{.InviterName}} has invited you to join HelloJohn as an administrator.</p>
<p><a href="{{.InviteLink}}">Accept Invitation</a></p>
<p>This invitation expires in {{.ExpiresIn}}.</p>
<p>— {{.ProductName}} Team</p>
</body>
</html>`

const adminInviteTextEN = `Hello {{.InviteeName}},

{{.InviterName}} has invited you to join HelloJohn as an administrator.

Accept your invitation: {{.InviteLink}}

This invitation expires in {{.ExpiresIn}}.

— {{.ProductName}} Team`

const adminInviteHTMLES = `<!DOCTYPE html>
<html>
<body>
<p>Hola {{.InviteeName}},</p>
<p>{{.InviterName}} te invitó a unirte a HelloJohn como administrador.</p>
<p><a href="{{.InviteLink}}">Aceptar Invitación</a></p>
<p>Esta invitación vence en {{.ExpiresIn}}.</p>
<p>— Equipo de {{.ProductName}}</p>
</body>
</html>`

const adminInviteTextES = `Hola {{.InviteeName}},

{{.InviterName}} te invitó a unirte a HelloJohn como administrador.

Aceptá tu invitación: {{.InviteLink}}

Esta invitación vence en {{.ExpiresIn}}.

— Equipo de {{.ProductName}}`

// ─── Template Data ───

type adminInviteVars struct {
	InviterName string
	InviteeName string
	InviteLink  string
	ExpiresIn   string
	ProductName string
}

// ─── Implementation ───

type systemEmailService struct {
	cfg    SystemSMTPConfig
	sender *SMTPSender
}

// NewSystemEmailService crea un SystemEmailService.
// Si cfg.IsConfigured() == false, los métodos retornan ErrSystemSMTPNotConfigured.
func NewSystemEmailService(cfg SystemSMTPConfig) SystemEmailService {
	svc := &systemEmailService{cfg: cfg}
	if cfg.IsConfigured() {
		svc.sender = NewSMTPSender(cfg.Host, cfg.Port, cfg.From, cfg.User, cfg.Password)
	}
	return svc
}

// compile-time check
var _ SystemEmailService = (*systemEmailService)(nil)

func (s *systemEmailService) SendAdminInvite(ctx context.Context, email, name, inviterName, inviteLink string) error {
	if s.sender == nil {
		return ErrSystemSMTPNotConfigured
	}

	lang := "en" // default; en el futuro se puede pasar el lang del admin

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

	return s.sender.Send(email, subject, htmlBody, textBody)
}

func (s *systemEmailService) SendSystemNotification(ctx context.Context, email, subject, body string) error {
	if s.sender == nil {
		return ErrSystemSMTPNotConfigured
	}
	htmlBody := fmt.Sprintf("<p>%s</p>", body)
	return s.sender.Send(email, subject, htmlBody, body)
}

func (s *systemEmailService) SendPaymentFailed(ctx context.Context, email, name string) error {
	if s.sender == nil {
		return ErrSystemSMTPNotConfigured
	}
	subject := "Action required: payment failed"
	htmlBody := fmt.Sprintf(`<p>Hi %s,</p><p>Your recent payment for HelloJohn failed. Please update your payment method to avoid service interruption.</p><p><a href="https://panel.hellojohn.io/admin/billing">Manage billing</a></p><p>— HelloJohn Team</p>`, name)
	textBody := fmt.Sprintf("Hi %s,\n\nYour recent payment for HelloJohn failed. Please update your payment method to avoid service interruption.\n\nManage billing: https://panel.hellojohn.io/admin/billing\n\n— HelloJohn Team", name)
	return s.sender.Send(email, subject, htmlBody, textBody)
}

func (s *systemEmailService) SendOnboardCredentials(ctx context.Context, toEmail, appName, claimURL string) error {
	if s.sender == nil {
		return ErrSystemSMTPNotConfigured
	}
	subject := fmt.Sprintf("Your HelloJohn app '%s' is ready", appName)
	htmlBody := fmt.Sprintf(`<p>Your app <strong>%s</strong> has been created on HelloJohn.</p><p>Claim your tenant to unlock full access:</p><p><a href="%s">Claim your app</a></p><p>This link expires in 30 days.</p><p>— HelloJohn Team</p>`, appName, claimURL)
	textBody := fmt.Sprintf("Your app '%s' has been created on HelloJohn.\n\nClaim your tenant:\n%s\n\nThis link expires in 30 days.\n\n— HelloJohn Team", appName, claimURL)
	return s.sender.Send(toEmail, subject, htmlBody, textBody)
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
