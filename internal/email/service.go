package emailv2

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	htemplate "html/template"
	"net/url"
	ttemplate "text/template"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	"github.com/google/uuid"
)

// ─── Errors ───

var (
	ErrNoSMTPConfig   = errors.New("email: no SMTP configuration for tenant")
	ErrTenantNotFound = errors.New("email: tenant not found")
	ErrTemplateRender = errors.New("email: template render failed")
	ErrSendFailed     = errors.New("email: send failed")
	ErrInvalidInput   = errors.New("email: invalid input")
)

// ─── Service Interface ───

// Service define las operaciones del servicio de email.
// Usa Store V2 internamente para resolver configuración SMTP y templates.
type Service interface {
	// GetSender obtiene un Sender configurado para el tenant.
	// tenantSlugOrID puede ser UUID o slug.
	GetSender(ctx context.Context, tenantSlugOrID string) (Sender, error)

	// SendVerificationEmail envía un email de verificación.
	SendVerificationEmail(ctx context.Context, req SendVerificationRequest) error

	// SendPasswordResetEmail envía un email de reset de password.
	SendPasswordResetEmail(ctx context.Context, req SendPasswordResetRequest) error

	// SendNotificationEmail envía una notificación genérica.
	SendNotificationEmail(ctx context.Context, req SendNotificationRequest) error

	// TestSMTP prueba la configuración SMTP de un tenant.
	// Si override no es nil, usa esa configuración en lugar de la del tenant.
	TestSMTP(ctx context.Context, tenantSlugOrID, recipientEmail string, override *SMTPConfig) error
}

// ─── Configuration ───

// ServiceConfig contiene la configuración del servicio de email.
type ServiceConfig struct {
	DAL       store.DataAccessLayer // Acceso a datos (Store V2)
	MasterKey string                // Clave maestra para descifrar passwords

	BaseURL   string        // URL base para links (ej: https://auth.example.com)
	VerifyTTL time.Duration // TTL de tokens de verificación (default 48h)
	ResetTTL  time.Duration // TTL de tokens de reset (default 1h)

	// Templates por defecto (opcional, se cargan de tenant si existen)
	DefaultVerifyHTMLTmpl string
	DefaultVerifyTextTmpl string
	DefaultResetHTMLTmpl  string
	DefaultResetTextTmpl  string

	SystemSMTP SystemSMTPConfig // SMTP global de fallback (opcional)
}

// ─── Implementation ───

type service struct {
	dal            store.DataAccessLayer
	senderProvider SenderProvider
	masterKey      string
	baseURL        string
	verifyTTL      time.Duration
	resetTTL       time.Duration

	// Templates compilados (defaults)
	defaultVerifyHTML *htemplate.Template
	defaultVerifyText *ttemplate.Template
	defaultResetHTML  *htemplate.Template
	defaultResetText  *ttemplate.Template
}

// NewService crea una nueva instancia del servicio de email.
func NewService(cfg ServiceConfig) (Service, error) {
	if cfg.DAL == nil {
		return nil, fmt.Errorf("DAL is required")
	}

	// Defaults
	if cfg.VerifyTTL == 0 {
		cfg.VerifyTTL = 48 * time.Hour
	}
	if cfg.ResetTTL == 0 {
		cfg.ResetTTL = 1 * time.Hour
	}

	s := &service{
		dal:            cfg.DAL,
		senderProvider: NewSenderProvider(cfg.DAL, cfg.MasterKey, cfg.SystemSMTP),
		masterKey:      cfg.MasterKey,
		baseURL:        cfg.BaseURL,
		verifyTTL:      cfg.VerifyTTL,
		resetTTL:       cfg.ResetTTL,
	}

	// Compilar templates por defecto si se proveen
	if cfg.DefaultVerifyHTMLTmpl != "" {
		t, err := htemplate.New("verify_html").Parse(cfg.DefaultVerifyHTMLTmpl)
		if err != nil {
			return nil, fmt.Errorf("parse default verify HTML template: %w", err)
		}
		s.defaultVerifyHTML = t
	}
	if cfg.DefaultVerifyTextTmpl != "" {
		t, err := ttemplate.New("verify_text").Parse(cfg.DefaultVerifyTextTmpl)
		if err != nil {
			return nil, fmt.Errorf("parse default verify text template: %w", err)
		}
		s.defaultVerifyText = t
	}
	if cfg.DefaultResetHTMLTmpl != "" {
		t, err := htemplate.New("reset_html").Parse(cfg.DefaultResetHTMLTmpl)
		if err != nil {
			return nil, fmt.Errorf("parse default reset HTML template: %w", err)
		}
		s.defaultResetHTML = t
	}
	if cfg.DefaultResetTextTmpl != "" {
		t, err := ttemplate.New("reset_text").Parse(cfg.DefaultResetTextTmpl)
		if err != nil {
			return nil, fmt.Errorf("parse default reset text template: %w", err)
		}
		s.defaultResetText = t
	}

	return s, nil
}

// ─── GetSender ───

func (s *service) GetSender(ctx context.Context, tenantSlugOrID string) (Sender, error) {
	return s.senderProvider.GetSender(ctx, tenantSlugOrID)
}

// ─── SendVerificationEmail ───

func (s *service) SendVerificationEmail(ctx context.Context, req SendVerificationRequest) error {
	log := logger.From(ctx).With(
		logger.String("op", "SendVerificationEmail"),
		logger.String("tenant", req.TenantSlugOrID),
		logger.String("email", req.Email),
	)

	// Validar input
	if req.TenantSlugOrID == "" || req.Email == "" || req.Token == "" {
		return ErrInvalidInput
	}

	// Resolver tenant para nombre y templates
	tenant, err := s.resolveTenant(ctx, req.TenantSlugOrID)
	if err != nil {
		log.Error("failed to resolve tenant", logger.Err(err))
		return ErrTenantNotFound
	}

	// Construir link
	link := s.buildVerifyLink(req.Token, req.RedirectURI, req.ClientID, req.TenantSlugOrID)

	// Preparar variables
	vars := VerifyVars{
		UserEmail: req.Email,
		Tenant:    tenant.Name,
		Link:      link,
		TTL:       formatDuration(req.TTL),
	}

	// Renderizar template (usando idioma del tenant como fallback)
	lang := tenant.Language
	if lang == "" {
		lang = "es"
	}
	htmlBody, textBody, err := s.renderVerify(tenant, vars, lang)
	if err != nil {
		log.Error("failed to render template", logger.Err(err))
		return fmt.Errorf("%w: %v", ErrTemplateRender, err)
	}

	// Obtener sender
	sender, err := s.senderProvider.GetSender(ctx, req.TenantSlugOrID)
	if err != nil {
		log.Error("failed to get sender", logger.Err(err))
		return fmt.Errorf("%w: %v", ErrNoSMTPConfig, err)
	}

	// Enviar
	subject := "Verificá tu email"
	if err := sender.Send(req.Email, subject, htmlBody, textBody); err != nil {
		diag := DiagnoseSMTP(err)
		log.Error("failed to send email",
			logger.Err(err),
			logger.String("diag_code", diag.Code),
			logger.Bool("temporary", diag.Temporary),
		)
		return fmt.Errorf("%w: %v", ErrSendFailed, err)
	}

	log.Info("verification email sent")
	return nil
}

// ─── SendPasswordResetEmail ───

func (s *service) SendPasswordResetEmail(ctx context.Context, req SendPasswordResetRequest) error {
	log := logger.From(ctx).With(
		logger.String("op", "SendPasswordResetEmail"),
		logger.String("tenant", req.TenantSlugOrID),
		logger.String("email", req.Email),
	)

	// Validar input
	if req.TenantSlugOrID == "" || req.Email == "" || req.Token == "" {
		return ErrInvalidInput
	}

	// Resolver tenant
	tenant, err := s.resolveTenant(ctx, req.TenantSlugOrID)
	if err != nil {
		log.Error("failed to resolve tenant", logger.Err(err))
		return ErrTenantNotFound
	}

	// Construir link
	var link string
	if req.CustomResetURL != "" {
		// Client tiene URL custom
		link = req.CustomResetURL
		if !containsToken(link) {
			link = addQueryParam(link, "token", req.Token)
		}
	} else {
		link = s.buildResetLink(req.Token, req.RedirectURI, req.ClientID, req.TenantSlugOrID)
	}

	// Preparar variables
	vars := ResetVars{
		UserEmail: req.Email,
		Tenant:    tenant.Name,
		Link:      link,
		TTL:       formatDuration(req.TTL),
	}

	// Renderizar template (usando idioma del tenant como fallback)
	lang := tenant.Language
	if lang == "" {
		lang = "es"
	}
	htmlBody, textBody, err := s.renderReset(tenant, vars, lang)
	if err != nil {
		log.Error("failed to render template", logger.Err(err))
		return fmt.Errorf("%w: %v", ErrTemplateRender, err)
	}

	// Obtener sender
	sender, err := s.senderProvider.GetSender(ctx, req.TenantSlugOrID)
	if err != nil {
		log.Error("failed to get sender", logger.Err(err))
		return fmt.Errorf("%w: %v", ErrNoSMTPConfig, err)
	}

	// Enviar
	subject := "Restablecé tu contraseña"
	if err := sender.Send(req.Email, subject, htmlBody, textBody); err != nil {
		diag := DiagnoseSMTP(err)
		log.Error("failed to send email",
			logger.Err(err),
			logger.String("diag_code", diag.Code),
			logger.Bool("temporary", diag.Temporary),
		)
		return fmt.Errorf("%w: %v", ErrSendFailed, err)
	}

	log.Info("password reset email sent")
	return nil
}

// ─── SendNotificationEmail ───

func (s *service) SendNotificationEmail(ctx context.Context, req SendNotificationRequest) error {
	log := logger.From(ctx).With(
		logger.String("op", "SendNotificationEmail"),
		logger.String("tenant", req.TenantSlugOrID),
		logger.String("email", req.Email),
		logger.String("template", req.TemplateID),
	)

	// Validar input
	if req.TenantSlugOrID == "" || req.Email == "" {
		return ErrInvalidInput
	}

	// Resolver tenant
	tenant, err := s.resolveTenant(ctx, req.TenantSlugOrID)
	if err != nil {
		log.Error("failed to resolve tenant", logger.Err(err))
		return ErrTenantNotFound
	}

	// Renderizar template del tenant si existe (usando idioma del tenant)
	lang := tenant.Language
	if lang == "" {
		lang = "es"
	}
	htmlBody, textBody, subject, err := s.renderNotification(tenant, req.TemplateID, req.TemplateVars, lang)
	if err != nil {
		log.Error("failed to render template", logger.Err(err))
		return fmt.Errorf("%w: %v", ErrTemplateRender, err)
	}

	// Override subject si se provee
	if req.Subject != "" {
		subject = req.Subject
	}

	// Obtener sender
	sender, err := s.senderProvider.GetSender(ctx, req.TenantSlugOrID)
	if err != nil {
		log.Error("failed to get sender", logger.Err(err))
		return fmt.Errorf("%w: %v", ErrNoSMTPConfig, err)
	}

	// Enviar
	if err := sender.Send(req.Email, subject, htmlBody, textBody); err != nil {
		diag := DiagnoseSMTP(err)
		log.Error("failed to send email",
			logger.Err(err),
			logger.String("diag_code", diag.Code),
			logger.Bool("temporary", diag.Temporary),
		)
		return fmt.Errorf("%w: %v", ErrSendFailed, err)
	}

	log.Info("notification email sent")
	return nil
}

// ─── TestSMTP ───

func (s *service) TestSMTP(ctx context.Context, tenantSlugOrID, recipientEmail string, override *SMTPConfig) error {
	log := logger.From(ctx).With(
		logger.String("op", "TestSMTP"),
		logger.String("tenant", tenantSlugOrID),
		logger.String("to", recipientEmail),
	)

	var sender Sender

	if override != nil {
		// Usar configuración override
		sender = FromConfig(*override)
		log.Debug("using override SMTP config",
			logger.String("host", override.Host),
			logger.Int("port", override.Port),
		)
	} else {
		// Usar configuración del tenant
		var err error
		sender, err = s.senderProvider.GetSender(ctx, tenantSlugOrID)
		if err != nil {
			log.Error("failed to get sender", logger.Err(err))
			return fmt.Errorf("%w: %v", ErrNoSMTPConfig, err)
		}
	}

	// Resolver tenant para nombre e idioma
	tenantName := tenantSlugOrID
	tenantLang := "es" // default
	if tenant, err := s.resolveTenant(ctx, tenantSlugOrID); err == nil {
		tenantName = tenant.Name
		if tenant.Language != "" {
			tenantLang = tenant.Language
		}
	}

	// Obtener contenido del email según idioma del tenant
	timestamp := time.Now().Format("02 Jan 2006, 15:04:05 MST")
	emailContent := GetTestEmailContent(tenantName, timestamp, tenantLang)

	// Enviar
	if err := sender.Send(recipientEmail, emailContent.Subject, emailContent.HTMLBody, emailContent.TextBody); err != nil {
		diag := DiagnoseSMTP(err)
		log.Error("test email failed",
			logger.Err(err),
			logger.String("diag_code", diag.Code),
			logger.Bool("temporary", diag.Temporary),
		)
		return fmt.Errorf("%w: %v (code: %s)", ErrSendFailed, err, diag.Code)
	}

	log.Info("test email sent successfully")
	return nil
}

// ─── Helpers ───

func (s *service) resolveTenant(ctx context.Context, tenantSlugOrID string) (*repository.Tenant, error) {
	tenants := s.dal.ConfigAccess().Tenants()

	// Intentar parsear como UUID
	if id, err := uuid.Parse(tenantSlugOrID); err == nil {
		tenant, err := tenants.GetByID(ctx, id.String())
		if err == nil {
			return tenant, nil
		}
	}

	// Intentar por slug
	return tenants.GetBySlug(ctx, tenantSlugOrID)
}

func (s *service) buildVerifyLink(token, redirect, clientID, tenantID string) string {
	u, _ := url.Parse(s.baseURL)
	u.Path = "/v2/auth/verify-email"
	q := u.Query()
	q.Set("token", token)
	if redirect != "" {
		q.Set("redirect_uri", redirect)
	}
	if clientID != "" {
		q.Set("client_id", clientID)
	}
	if tenantID != "" {
		q.Set("tenant_id", tenantID)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (s *service) buildResetLink(token, redirect, clientID, tenantID string) string {
	u, _ := url.Parse(s.baseURL)
	u.Path = "/v2/auth/reset"
	q := u.Query()
	q.Set("token", token)
	if redirect != "" {
		q.Set("redirect_uri", redirect)
	}
	if clientID != "" {
		q.Set("client_id", clientID)
	}
	if tenantID != "" {
		q.Set("tenant_id", tenantID)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (s *service) renderVerify(tenant *repository.Tenant, vars VerifyVars, lang string) (html, text string, err error) {
	// Intentar usar template del tenant si existe
	if tpl := s.getTemplateForLang(tenant, "verify_email", lang); tpl != nil && tpl.Body != "" {
		return s.renderTemplateStrings(tpl.Body, "", vars)
	}

	// Usar templates por defecto compilados
	if s.defaultVerifyHTML != nil && s.defaultVerifyText != nil {
		return s.renderDefaultTemplates(s.defaultVerifyHTML, s.defaultVerifyText, vars)
	}

	// Fallback mínimo
	html = fmt.Sprintf(`<p>Hola %s,</p><p>Verificá tu email: <a href="%s">%s</a></p>`,
		vars.UserEmail, vars.Link, vars.Link)
	text = fmt.Sprintf("Hola %s, verificá tu email visitando: %s", vars.UserEmail, vars.Link)
	return html, text, nil
}

func (s *service) renderReset(tenant *repository.Tenant, vars ResetVars, lang string) (html, text string, err error) {
	// Intentar usar template del tenant si existe
	if tpl := s.getTemplateForLang(tenant, "reset_password", lang); tpl != nil && tpl.Body != "" {
		return s.renderTemplateStrings(tpl.Body, "", vars)
	}

	// Usar templates por defecto compilados
	if s.defaultResetHTML != nil && s.defaultResetText != nil {
		return s.renderDefaultTemplates(s.defaultResetHTML, s.defaultResetText, vars)
	}

	// Fallback mínimo
	html = fmt.Sprintf(`<p>Hola %s,</p><p>Restablecé tu contraseña: <a href="%s">%s</a></p>`,
		vars.UserEmail, vars.Link, vars.Link)
	text = fmt.Sprintf("Hola %s, restablecé tu contraseña visitando: %s", vars.UserEmail, vars.Link)
	return html, text, nil
}

func (s *service) renderNotification(tenant *repository.Tenant, templateID string, vars map[string]any, lang string) (html, text, subject string, err error) {
	// Intentar usar template del tenant
	if tpl := s.getTemplateForLang(tenant, templateID, lang); tpl != nil && tpl.Body != "" {
		html, text, err = s.renderTemplateStrings(tpl.Body, "", vars)
		return html, text, tpl.Subject, err
	}

	// Fallback genérico
	subject = "Notificación"
	html = "<p>Notificación del sistema</p>"
	text = "Notificación del sistema"
	return html, text, subject, nil
}

// getTemplateForLang obtiene un template para un idioma específico con fallback al idioma del tenant
func (s *service) getTemplateForLang(tenant *repository.Tenant, templateID, lang string) *repository.EmailTemplate {
	if tenant.Settings.Mailing == nil || tenant.Settings.Mailing.Templates == nil {
		return nil
	}

	templates := tenant.Settings.Mailing.Templates

	// Intentar idioma solicitado
	if langTemplates, ok := templates[lang]; ok {
		if tpl, ok := langTemplates[templateID]; ok {
			return &tpl
		}
	}

	// Fallback al idioma del tenant
	tenantLang := tenant.Language
	if tenantLang == "" {
		tenantLang = "es" // Default
	}
	if lang != tenantLang {
		if langTemplates, ok := templates[tenantLang]; ok {
			if tpl, ok := langTemplates[templateID]; ok {
				return &tpl
			}
		}
	}

	return nil
}

func (s *service) renderTemplateStrings(htmlTmpl, textTmpl string, data any) (string, string, error) {
	var htmlBuf, textBuf bytes.Buffer

	if htmlTmpl != "" {
		t, err := htemplate.New("html").Parse(htmlTmpl)
		if err != nil {
			return "", "", err
		}
		if err := t.Execute(&htmlBuf, data); err != nil {
			return "", "", err
		}
	}

	if textTmpl != "" {
		t, err := ttemplate.New("text").Parse(textTmpl)
		if err != nil {
			return "", "", err
		}
		if err := t.Execute(&textBuf, data); err != nil {
			return "", "", err
		}
	}

	return htmlBuf.String(), textBuf.String(), nil
}

func (s *service) renderDefaultTemplates(htmlTmpl *htemplate.Template, textTmpl *ttemplate.Template, data any) (string, string, error) {
	var htmlBuf, textBuf bytes.Buffer

	if err := htmlTmpl.Execute(&htmlBuf, data); err != nil {
		return "", "", err
	}
	if err := textTmpl.Execute(&textBuf, data); err != nil {
		return "", "", err
	}

	return htmlBuf.String(), textBuf.String(), nil
}

func formatDuration(d time.Duration) string {
	if d == 0 {
		return ""
	}
	hours := int(d.Hours())
	if hours >= 24 {
		days := hours / 24
		if days == 1 {
			return "1 día"
		}
		return fmt.Sprintf("%d días", days)
	}
	if hours >= 1 {
		if hours == 1 {
			return "1 hora"
		}
		return fmt.Sprintf("%d horas", hours)
	}
	minutes := int(d.Minutes())
	if minutes == 1 {
		return "1 minuto"
	}
	return fmt.Sprintf("%d minutos", minutes)
}

func containsToken(link string) bool {
	u, err := url.Parse(link)
	if err != nil {
		return false
	}
	return u.Query().Get("token") != ""
}

func addQueryParam(link, key, value string) string {
	u, err := url.Parse(link)
	if err != nil {
		return link + "?" + key + "=" + url.QueryEscape(value)
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}
