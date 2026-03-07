package emailv2

import "fmt"

// ─── Test Email Templates ───
// Templates para el email de prueba de configuración SMTP

const testEmailBaseStyles = `
body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #f4f4f7; color: #333; margin: 0; padding: 0; }
.container { width: 100%%; max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }
.header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); padding: 40px; text-align: center; }
.header h1 { color: #ffffff; margin: 0 0 8px 0; font-size: 28px; font-weight: 700; }
.header .subtitle { color: rgba(255,255,255,0.9); font-size: 14px; }
.content { padding: 40px; line-height: 1.7; }
.success-badge { display: inline-block; background: linear-gradient(135deg, #11998e 0%%, #38ef7d 100%%); color: white; padding: 8px 20px; border-radius: 50px; font-size: 14px; font-weight: 600; margin-bottom: 24px; }
.info-card { background: #f8f9ff; border-left: 4px solid #667eea; padding: 20px; margin: 24px 0; border-radius: 0 8px 8px 0; }
.info-card strong { color: #667eea; }
.footer { background-color: #1a1a2e; padding: 30px 40px; text-align: center; }
.footer p { color: #8b8b9a; font-size: 12px; margin: 0 0 8px 0; }
.footer .brand { color: #667eea; font-weight: 600; font-size: 14px; }
.timestamp { color: #999; font-size: 12px; margin-top: 16px; }
`

// TestEmailContent contiene el contenido del email de prueba
type TestEmailContent struct {
	Subject  string
	HTMLBody string
	TextBody string
}

// GetTestEmailContent retorna el contenido del email de prueba según el idioma
func GetTestEmailContent(tenantName, timestamp, lang string) TestEmailContent {
	switch lang {
	case "en":
		return testEmailEN(tenantName, timestamp)
	default:
		return testEmailES(tenantName, timestamp)
	}
}

func testEmailES(tenantName, timestamp string) TestEmailContent {
	return TestEmailContent{
		Subject: fmt.Sprintf("✅ Mailing Configurado - %s", tenantName),
		HTMLBody: fmt.Sprintf(`<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>%s</style>
</head>
<body>
  <div style="padding: 40px 20px;">
    <div class="container">
      <div class="header">
        <h1>🚀 HelloJohn</h1>
        <div class="subtitle">Identity & Authentication Platform</div>
      </div>
      <div class="content">
        <div class="success-badge">✓ Configuración Exitosa</div>
        <h2 style="margin-top: 0; color: #333; font-size: 24px;">¡Tu mailing está listo!</h2>
        <p>Hola,</p>
        <p>Este es un correo de prueba que confirma que la configuración SMTP para <strong>%s</strong> está funcionando correctamente.</p>
        
        <div class="info-card">
          <strong>¿Qué significa esto?</strong><br>
          Tu tenant puede enviar emails de verificación, recuperación de contraseña y notificaciones sin problemas.
        </div>
        
        <p>Si no solicitaste esta prueba, puedes ignorar este mensaje.</p>
        
        <p class="timestamp">Enviado: %s</p>
      </div>
      <div class="footer">
        <p class="brand">HelloJohn</p>
        <p>Open Source Identity Platform</p>
        <p>Este es un mensaje automático de prueba.</p>
      </div>
    </div>
  </div>
</body>
</html>`, testEmailBaseStyles, tenantName, timestamp),
		TextBody: fmt.Sprintf(`✅ Mailing Configurado - %s

¡Tu mailing está listo!

Este es un correo de prueba que confirma que la configuración SMTP para %s está funcionando correctamente.

Enviado: %s

--
HelloJohn - Open Source Identity Platform`, tenantName, tenantName, timestamp),
	}
}

func testEmailEN(tenantName, timestamp string) TestEmailContent {
	return TestEmailContent{
		Subject: fmt.Sprintf("✅ Mailing Configured - %s", tenantName),
		HTMLBody: fmt.Sprintf(`<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>%s</style>
</head>
<body>
  <div style="padding: 40px 20px;">
    <div class="container">
      <div class="header">
        <h1>🚀 HelloJohn</h1>
        <div class="subtitle">Identity & Authentication Platform</div>
      </div>
      <div class="content">
        <div class="success-badge">✓ Configuration Successful</div>
        <h2 style="margin-top: 0; color: #333; font-size: 24px;">Your mailing is ready!</h2>
        <p>Hello,</p>
        <p>This is a test email confirming that the SMTP configuration for <strong>%s</strong> is working correctly.</p>
        
        <div class="info-card">
          <strong>What does this mean?</strong><br>
          Your tenant can send verification emails, password recovery, and notifications without issues.
        </div>
        
        <p>If you didn't request this test, you can ignore this message.</p>
        
        <p class="timestamp">Sent: %s</p>
      </div>
      <div class="footer">
        <p class="brand">HelloJohn</p>
        <p>Open Source Identity Platform</p>
        <p>This is an automated test message.</p>
      </div>
    </div>
  </div>
</body>
</html>`, testEmailBaseStyles, tenantName, timestamp),
		TextBody: fmt.Sprintf(`✅ Mailing Configured - %s

Your mailing is ready!

This is a test email confirming that the SMTP configuration for %s is working correctly.

Sent: %s

--
HelloJohn - Open Source Identity Platform`, tenantName, tenantName, timestamp),
	}
}
