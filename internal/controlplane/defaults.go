package controlplane

import "github.com/dropDatabas3/hellojohn/internal/domain/repository"

// DefaultLanguage es el idioma por defecto para nuevos tenants.
const DefaultLanguage = "es"

// DefaultEmailTemplates retorna los templates de email por defecto para todos los idiomas.
func DefaultEmailTemplates() map[string]map[string]repository.EmailTemplate {
	return map[string]map[string]repository.EmailTemplate{
		"es": defaultTemplatesES(),
		"en": defaultTemplatesEN(),
	}
}

// ─── Estilos Base ───

const baseStyles = `
body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #f4f4f7; color: #333; margin: 0; padding: 0; -webkit-font-smoothing: antialiased; }
.container { width: 100%; max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
.header { background-color: #1a1a1a; padding: 30px 40px; text-align: center; }
.header h1 { color: #ffffff; margin: 0; font-size: 24px; font-weight: 600; letter-spacing: -0.5px; }
.content { padding: 40px; line-height: 1.6; }
.button { display: inline-block; background-color: #0070f3; color: #ffffff; text-decoration: none; padding: 12px 30px; border-radius: 5px; font-weight: 600; margin-top: 20px; }
.footer { background-color: #f9f9f9; padding: 20px 40px; text-align: center; font-size: 12px; color: #999; border-top: 1px solid #eee; }
.info-box { background-color: #f0f7ff; border-left: 4px solid #0070f3; padding: 15px; margin: 20px 0; border-radius: 4px; font-size: 14px; color: #0056b3; }
.warning-box { background-color: #fff8f0; border-left: 4px solid #f5a623; padding: 15px; margin: 20px 0; border-radius: 4px; font-size: 14px; color: #8a5d00; }
`

const (
	footerES = "Todos los derechos reservados."
	footerEN = "All rights reserved."
)

func wrapHTML(content, footer string) string {
	return `<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>` + baseStyles + `</style>
</head>
<body>
  <div style="padding: 40px 0;">
    <div class="container">
      <div class="header">
        <h1>{{.Tenant}}</h1>
      </div>
      <div class="content">
        ` + content + `
      </div>
      <div class="footer">
        <p>&copy; 2024 {{.Tenant}}. ` + footer + `</p>
      </div>
    </div>
  </div>
</body>
</html>`
}

// ─── Templates ES ───

func defaultTemplatesES() map[string]repository.EmailTemplate {
	return map[string]repository.EmailTemplate{
		"verify_email": {
			Subject: "Verifica tu correo electrónico",
			Body: wrapHTML(`
        <h2 style="margin-top: 0; color: #333;">Bienvenido a {{.Tenant}}</h2>
        <p>Hola <strong>{{.UserEmail}}</strong>,</p>
        <p>Gracias por registrarte. Para comenzar, necesitamos confirmar que esta dirección de correo electrónico te pertenece.</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{.Link}}" class="button" style="color: #ffffff;">Verificar mi cuenta</a>
        </div>
        <p style="font-size: 14px; color: #666;">O copia y pega el siguiente enlace en tu navegador:</p>
        <p style="font-size: 12px; color: #888; background: #eee; padding: 10px; border-radius: 4px; word-break: break-all;">{{.Link}}</p>
        <div class="info-box">Este enlace caducará en <strong>{{.TTL}}</strong>.</div>
        <p>Si no creaste esta cuenta, puedes ignorar este mensaje.</p>
        `, footerES),
		},
		"reset_password": {
			Subject: "Restablecer tu contraseña",
			Body: wrapHTML(`
        <h2 style="margin-top: 0; color: #333;">Recuperación de Contraseña</h2>
        <p>Hola <strong>{{.UserEmail}}</strong>,</p>
        <p>Hemos recibido una solicitud para restablecer la contraseña de tu cuenta en {{.Tenant}}.</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{.Link}}" class="button" style="background-color: #27272a; color: #ffffff;">Restablecer Contraseña</a>
        </div>
        <p>Si no solicitaste este cambio, por favor ignora este correo. Tu contraseña actual seguirá funcionando.</p>
        <div class="warning-box">Por seguridad, este enlace solo es válido por <strong>{{.TTL}}</strong>.</div>
        `, footerES),
		},
		"user_blocked": {
			Subject: "Aviso importante: Cuenta bloqueada",
			Body: wrapHTML(`
        <h2 style="margin-top: 0; color: #d93025;">Acceso Restringido</h2>
        <p>Hola <strong>{{.UserEmail}}</strong>,</p>
        <p>Tu acceso a {{.Tenant}} ha sido suspendido temporalmente debido a una acción administrativa o de seguridad.</p>
        <div class="warning-box" style="border-color: #d93025; background-color: #fff5f5; color: #b71c1c;">
          <strong>Motivo:</strong> {{.Reason}}<br>
          <strong>Vigencia:</strong> Hasta {{.Until}}
        </div>
        <p>Si consideras que esto es un error, por favor ponte en contacto con nuestro equipo de soporte inmediatamente.</p>
        `, footerES),
		},
		"user_unblocked": {
			Subject: "Tu cuenta ha sido reactivada",
			Body: wrapHTML(`
        <h2 style="margin-top: 0; color: #188038;">¡Estás de vuelta!</h2>
        <p>Hola <strong>{{.UserEmail}}</strong>,</p>
        <p>Nos complace informarte que las restricciones en tu cuenta de {{.Tenant}} han sido levantadas.</p>
        <p>Ya tienes acceso completo a todos nuestros servicios nuevamente.</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="#" class="button" style="background-color: #188038; color: #ffffff;">Iniciar Sesión</a>
        </div>
        <p>Gracias por tu paciencia.</p>
        `, footerES),
		},
	}
}

// ─── Templates EN ───

func defaultTemplatesEN() map[string]repository.EmailTemplate {
	return map[string]repository.EmailTemplate{
		"verify_email": {
			Subject: "Verify your email address",
			Body: wrapHTML(`
        <h2 style="margin-top: 0; color: #333;">Welcome to {{.Tenant}}</h2>
        <p>Hello <strong>{{.UserEmail}}</strong>,</p>
        <p>Thank you for signing up. To get started, we need to confirm that this email address belongs to you.</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{.Link}}" class="button" style="color: #ffffff;">Verify my account</a>
        </div>
        <p style="font-size: 14px; color: #666;">Or copy and paste the following link in your browser:</p>
        <p style="font-size: 12px; color: #888; background: #eee; padding: 10px; border-radius: 4px; word-break: break-all;">{{.Link}}</p>
        <div class="info-box">This link will expire in <strong>{{.TTL}}</strong>.</div>
        <p>If you didn't create this account, you can ignore this message.</p>
        `, footerEN),
		},
		"reset_password": {
			Subject: "Reset your password",
			Body: wrapHTML(`
        <h2 style="margin-top: 0; color: #333;">Password Recovery</h2>
        <p>Hello <strong>{{.UserEmail}}</strong>,</p>
        <p>We received a request to reset the password for your account at {{.Tenant}}.</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="{{.Link}}" class="button" style="background-color: #27272a; color: #ffffff;">Reset Password</a>
        </div>
        <p>If you didn't request this change, please ignore this email. Your current password will continue to work.</p>
        <div class="warning-box">For security, this link is only valid for <strong>{{.TTL}}</strong>.</div>
        `, footerEN),
		},
		"user_blocked": {
			Subject: "Important notice: Account blocked",
			Body: wrapHTML(`
        <h2 style="margin-top: 0; color: #d93025;">Access Restricted</h2>
        <p>Hello <strong>{{.UserEmail}}</strong>,</p>
        <p>Your access to {{.Tenant}} has been temporarily suspended due to an administrative or security action.</p>
        <div class="warning-box" style="border-color: #d93025; background-color: #fff5f5; color: #b71c1c;">
          <strong>Reason:</strong> {{.Reason}}<br>
          <strong>Until:</strong> {{.Until}}
        </div>
        <p>If you believe this is an error, please contact our support team immediately.</p>
        `, footerEN),
		},
		"user_unblocked": {
			Subject: "Your account has been reactivated",
			Body: wrapHTML(`
        <h2 style="margin-top: 0; color: #188038;">You're back!</h2>
        <p>Hello <strong>{{.UserEmail}}</strong>,</p>
        <p>We're pleased to inform you that the restrictions on your {{.Tenant}} account have been lifted.</p>
        <p>You now have full access to all our services again.</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="#" class="button" style="background-color: #188038; color: #ffffff;">Sign In</a>
        </div>
        <p>Thank you for your patience.</p>
        `, footerEN),
		},
	}
}
