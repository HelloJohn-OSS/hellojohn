package emailv2

import (
	"net"
	"strings"
	"time"
)

// SMTPDiag contiene información de diagnóstico de un error SMTP.
type SMTPDiag struct {
	Code       string        // auth|tls|dial|timeout|rate_limited|invalid_recipient|rejected|network|unknown
	Temporary  bool          // si conviene reintentar
	RetryAfter time.Duration // 0 si no se pudo inferir
}

// DiagnoseSMTP analiza un error SMTP y retorna información de diagnóstico.
func DiagnoseSMTP(err error) SMTPDiag {
	if err == nil {
		return SMTPDiag{Code: "unknown"}
	}
	s := strings.ToLower(err.Error())

	// timeouts
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return SMTPDiag{Code: "timeout", Temporary: true}
	}
	if strings.Contains(s, "timeout") || strings.Contains(s, "i/o timeout") {
		return SMTPDiag{Code: "timeout", Temporary: true}
	}

	// dial/conn/dns
	if strings.Contains(s, "connection refused") ||
		strings.Contains(s, "connectex:") || // windows
		strings.Contains(s, "no such host") ||
		strings.Contains(s, "dial tcp") {
		return SMTPDiag{Code: "dial", Temporary: true}
	}

	// tls/handshake/cert
	if strings.Contains(s, "x509:") ||
		strings.Contains(s, "tls") && (strings.Contains(s, "handshake") || strings.Contains(s, "certificate")) {
		return SMTPDiag{Code: "tls", Temporary: false}
	}

	// auth (credenciales/permiso)
	if strings.Contains(s, "5.7.8") || strings.Contains(s, "535") ||
		strings.Contains(s, "username and password not accepted") ||
		strings.Contains(s, "authentication failed") ||
		strings.Contains(s, "auth") && strings.Contains(s, "failed") {
		return SMTPDiag{Code: "auth", Temporary: false}
	}

	// rate limit / throttling temporal (4.x.x)
	if strings.Contains(s, "4.7.0") ||
		strings.Contains(s, "rate limit") ||
		strings.Contains(s, "try again later") ||
		strings.Contains(s, "temporarily unavailable") ||
		strings.Contains(s, "451") || strings.Contains(s, "421") {
		return SMTPDiag{Code: "rate_limited", Temporary: true}
	}

	// destinatario inválido
	if strings.Contains(s, "5.1.1") || strings.Contains(s, "user unknown") ||
		strings.Contains(s, "mailbox not found") {
		return SMTPDiag{Code: "invalid_recipient", Temporary: false}
	}

	// políticas/DMARC/SPF/rechazos 5.7.1
	if strings.Contains(s, "5.7.1") ||
		strings.Contains(s, "message rejected") ||
		strings.Contains(s, "policy") ||
		strings.Contains(s, "dmarc") || strings.Contains(s, "spf") {
		return SMTPDiag{Code: "rejected", Temporary: false}
	}

	// resto de errores de red
	if _, ok := err.(net.Error); ok {
		return SMTPDiag{Code: "network", Temporary: true}
	}
	return SMTPDiag{Code: "unknown", Temporary: false}
}
