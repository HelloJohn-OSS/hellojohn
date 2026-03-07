package emailv2

import "context"

// Sender es la interfaz para enviar emails.
// Implementada por SMTPSender.
type Sender interface {
	// Send envía un email con contenido HTML y texto plano.
	// El destinatario recibe ambas versiones como multipart/alternative.
	Send(to string, subject string, htmlBody string, textBody string) error
}

// SenderProvider resuelve un Sender configurado para un tenant.
type SenderProvider interface {
	// GetSender obtiene un Sender configurado para el tenant especificado.
	// tenantSlugOrID puede ser UUID o slug del tenant.
	GetSender(ctx context.Context, tenantSlugOrID string) (Sender, error)
}

// TemplateLoader carga y renderiza templates de email.
type TemplateLoader interface {
	// LoadVerify carga el template de verificación de email.
	LoadVerify(tenantSlug string) (html, text string, err error)

	// LoadReset carga el template de reset de password.
	LoadReset(tenantSlug string) (html, text string, err error)

	// LoadNotification carga un template genérico por ID.
	LoadNotification(tenantSlug, templateID string) (subject, html, text string, err error)

	// RenderVerify renderiza el template de verificación con las variables.
	RenderVerify(html, text string, vars VerifyVars) (renderedHTML, renderedText string, err error)

	// RenderReset renderiza el template de reset con las variables.
	RenderReset(html, text string, vars ResetVars) (renderedHTML, renderedText string, err error)

	// RenderNotification renderiza un template genérico con variables arbitrarias.
	RenderNotification(html, text string, vars map[string]any) (renderedHTML, renderedText string, err error)
}
