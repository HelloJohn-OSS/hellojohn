package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	cache "github.com/dropDatabas3/hellojohn/internal/cache"
	emailv2 "github.com/dropDatabas3/hellojohn/internal/email"
	dtoa "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// ── Sentinel Errors ──

var (
	ErrMagicLinkDisabled         = errors.New("magic link is disabled for this tenant")
	ErrOTPDisabled               = errors.New("otp is disabled for this tenant")
	ErrRateLimited               = errors.New("rate limit exceeded, try again in a minute")
	ErrInvalidOrExpiredMagicLink = errors.New("invalid or expired magic link")
	ErrInvalidOrExpiredOTP       = errors.New("invalid or expired otp")
	ErrTooManyAttempts           = errors.New("too many failed attempts, request a new code")
	ErrAuthenticationFailed      = errors.New("authentication failed")
	ErrInvalidRedirectURI        = errors.New("redirect_uri not in client's registered URIs")
	ErrCacheNotConfigured        = errors.New("cache not configured")
	ErrDailyLimitExceeded        = errors.New("daily rate limit exceeded")
	ErrInvalidOrExpiredMagicCode = errors.New("invalid or expired magic link code")
)

// ── Deps ──

// PasswordlessDeps contiene las dependencias específicas del servicio passwordless.
type PasswordlessDeps struct {
	DAL        store.DataAccessLayer
	Issuer     *jwtx.Issuer
	Cache      cache.Client
	RefreshTTL time.Duration
	Email      emailv2.Service
	BaseURL    string // URL base para construir magic link URLs
	AuditBus   *audit.AuditBus
}

// ── Request DTOs ──

// MagicLinkRequest describe la solicitud para enviar un magic link.
type MagicLinkRequest struct {
	TenantSlug  string `json:"tenant_id"`
	Email       string `json:"email"`
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
}

// OTPRequest describe la solicitud para enviar un OTP por email.
type OTPRequest struct {
	TenantSlug string `json:"tenant_id"`
	Email      string `json:"email"`
	ClientID   string `json:"client_id"`
}

// VerifyOTPRequest describe la verificación de un OTP.
type VerifyOTPRequest struct {
	TenantSlug string `json:"tenant_id"`
	Email      string `json:"email"`
	Code       string `json:"code"`
	ClientID   string `json:"client_id"`
}

// ExchangeMagicLinkCodeRequest exchanges an ephemeral code for tokens.
type ExchangeMagicLinkCodeRequest struct {
	Code string `json:"code"`
}

// ── Cache Session Structs ──

// magicLinkSession se almacena en caché cuando se envía un magic link.
type magicLinkSession struct {
	Email       string `json:"email"`
	TenantID    string `json:"tenant_id"`
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
}

// otpSession se almacena en caché cuando se envía un OTP.
type otpSession struct {
	CodeHash  string    `json:"code_hash"`
	Attempts  int       `json:"attempts"`
	TenantID  string    `json:"tenant_id"`
	ClientID  string    `json:"client_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ── Interface ──

// PasswordlessService define los métodos para autenticación sin contraseña.
type PasswordlessService interface {
	// Magic Link
	SendMagicLink(ctx context.Context, req MagicLinkRequest) error
	VerifyMagicLink(ctx context.Context, token string) (*dtoa.LoginResponse, error)
	ConsumeMagicLink(ctx context.Context, token string) (string, error)
	ExchangeMagicLinkCode(ctx context.Context, code string) (*dtoa.LoginResponse, error)

	// OTP Email
	SendOTPEmail(ctx context.Context, req OTPRequest) error
	VerifyOTPEmail(ctx context.Context, req VerifyOTPRequest) (*dtoa.LoginResponse, error)
}

// ── Cache Key Helpers ──

// MagicLinkCacheKey genera la key de caché para un magic link token.
func MagicLinkCacheKey(token string) string {
	return fmt.Sprintf("magic_link:%s", token)
}

// MagicLinkCodeCacheKey generates cache key for ephemeral continuation codes.
func MagicLinkCodeCacheKey(code string) string {
	return fmt.Sprintf("magic_link_code:%s", code)
}

// OTPCacheKey genera la key de caché para un OTP por email.
func OTPCacheKey(tenantID, email string) string {
	return fmt.Sprintf("otp_email:%s:%s", tenantID, email)
}

// OTPRateLimitKey genera la key de rate limiting para un OTP.
func OTPRateLimitKey(tenantSlug, email string) string {
	return fmt.Sprintf("rl:otp:%s:%s", tenantSlug, email)
}

// hashOTP genera un hash SHA-256 del código OTP para almacenamiento seguro.
func hashOTP(code string) string {
	h := sha256.Sum256([]byte(code))
	return fmt.Sprintf("%x", h)
}
