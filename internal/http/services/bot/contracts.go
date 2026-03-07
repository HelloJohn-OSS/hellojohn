package bot

import (
	"context"
	"time"
)

// ValidationResult es el resultado de validar un token de bot protection.
type ValidationResult struct {
	Success            bool
	ErrorCodes         []string // De Cloudflare: "missing-input-secret", "invalid-input-response", etc.
	Hostname           string   // Hostname donde fue generado el token (para validación extra)
	ChallengeTimestamp time.Time
}

// ResolvedConfig es la config efectiva para un tenant (global merged con tenant-specific).
type ResolvedConfig struct {
	Enabled              bool
	Provider             string
	SecretKey            string // Siempre decriptado, nunca expuesto fuera del service
	SiteKey              string
	ProtectLogin         bool
	ProtectRegistration  bool
	ProtectPasswordReset bool
	Appearance           string
	Theme                string
}

// BotProtectionService valida tokens anti-bot y resuelve config por tenant.
type BotProtectionService interface {
	// Validate verifica un token de bot protection para el tenant dado.
	// Si la protección está deshabilitada para este tenant/endpoint, retorna nil.
	// Si el token es inválido, retorna error.
	// remoteIP puede estar vacío (Cloudflare lo acepta, pero mejora la detección si se provee).
	Validate(ctx context.Context, req ValidateRequest) error

	// ResolveConfig retorna la config efectiva para un tenant.
	// Usado por el endpoint /v2/auth/config para exponer el siteKey al frontend.
	ResolveConfig(ctx context.Context, tenantSlug string) (*ResolvedConfig, error)
}

// ValidateRequest agrupa los parámetros de validación.
type ValidateRequest struct {
	Token      string // cf-turnstile-response del frontend
	RemoteIP   string // IP del cliente (opcional pero recomendado)
	TenantSlug string // Para resolver config tenant-specific
	Endpoint   string // "login" | "register" | "password_reset" — para chequear scope
}

// Errores del paquete bot.
var (
	ErrTokenMissing = errTokenMissing{}
	ErrTokenInvalid = errTokenInvalid{}
)

type errTokenMissing struct{}

func (e errTokenMissing) Error() string { return "bot: turnstile token is required" }

type errTokenInvalid struct{}

func (e errTokenInvalid) Error() string { return "bot: turnstile token validation failed" }
