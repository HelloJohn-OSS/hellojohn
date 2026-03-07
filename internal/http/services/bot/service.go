package bot

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/security/secretbox"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

const turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// Deps son las dependencias del BotProtectionService.
type Deps struct {
	DAL store.DataAccessLayer

	// Config global (fallback cuando el tenant no tiene config propia)
	GlobalEnabled      bool
	GlobalProvider     string
	GlobalSecretKey    string // Plain text, cargado desde env en wiring
	GlobalSiteKey      string
	GlobalProtectLogin bool
	GlobalProtectReg   bool
	GlobalProtectReset bool

	// HTTP client para llamar a Cloudflare (inyectable para tests)
	HTTPClient *http.Client
}

type botService struct {
	deps Deps
}

// New crea una nueva instancia del BotProtectionService real.
func New(deps Deps) BotProtectionService {
	if deps.HTTPClient == nil {
		deps.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	return &botService{deps: deps}
}

// ResolveConfig retorna la config efectiva para un tenant.
// Prioridad: tenant config → global config → disabled.
func (s *botService) ResolveConfig(ctx context.Context, tenantSlug string) (*ResolvedConfig, error) {
	// 1. Intentar cargar config del tenant
	if tenantSlug != "" {
		tda, err := s.deps.DAL.ForTenant(ctx, tenantSlug)
		if err == nil {
			settings := tda.Settings()
			if settings != nil && settings.BotProtection != nil && settings.BotProtection.Enabled {
				cfg := settings.BotProtection
				secretKey := ""
				if cfg.TurnstileSecretEnc != "" {
					decrypted, decErr := secretbox.Decrypt(cfg.TurnstileSecretEnc)
					if decErr != nil {
						return nil, fmt.Errorf("bot: failed to decrypt tenant secret: %w", decErr)
					}
					secretKey = decrypted
				}
				return &ResolvedConfig{
					Enabled:              true,
					Provider:             cfg.Provider,
					SecretKey:            secretKey,
					SiteKey:              cfg.TurnstileSiteKey,
					ProtectLogin:         cfg.ProtectLogin,
					ProtectRegistration:  cfg.ProtectRegistration,
					ProtectPasswordReset: cfg.ProtectPasswordReset,
					Appearance:           cfg.Appearance,
					Theme:                cfg.Theme,
				}, nil
			}
		}
	}

	// 2. Fallback a config global
	if !s.deps.GlobalEnabled || s.deps.GlobalSecretKey == "" {
		return &ResolvedConfig{Enabled: false}, nil
	}

	return &ResolvedConfig{
		Enabled:              true,
		Provider:             s.deps.GlobalProvider,
		SecretKey:            s.deps.GlobalSecretKey,
		SiteKey:              s.deps.GlobalSiteKey,
		ProtectLogin:         s.deps.GlobalProtectLogin,
		ProtectRegistration:  s.deps.GlobalProtectReg,
		ProtectPasswordReset: s.deps.GlobalProtectReset,
		Appearance:           "execute",
		Theme:                "auto",
	}, nil
}

// Validate verifica un token Turnstile contra la API de Cloudflare.
func (s *botService) Validate(ctx context.Context, req ValidateRequest) error {
	cfg, err := s.ResolveConfig(ctx, req.TenantSlug)
	if err != nil {
		return err
	}

	// Si la protección está deshabilitada, pass-through limpio
	if !cfg.Enabled {
		return nil
	}

	// Verificar si este endpoint está protegido
	if !s.isEndpointProtected(cfg, req.Endpoint) {
		return nil
	}

	// Token requerido
	if strings.TrimSpace(req.Token) == "" {
		return ErrTokenMissing
	}

	// Llamar a Cloudflare
	result, callErr := s.callTurnstileAPI(ctx, cfg.SecretKey, req.Token, req.RemoteIP)
	if callErr != nil {
		// Error de red/timeout → fail open (no bloquear al usuario por problemas de Cloudflare)
		// Log el error pero dejar pasar
		return nil
	}

	if !result.Success {
		return ErrTokenInvalid
	}

	return nil
}

func (s *botService) isEndpointProtected(cfg *ResolvedConfig, endpoint string) bool {
	switch endpoint {
	case "login":
		return cfg.ProtectLogin
	case "register":
		return cfg.ProtectRegistration
	case "password_reset":
		return cfg.ProtectPasswordReset
	default:
		return false
	}
}

// turnstileResponse es la respuesta de la API de Cloudflare.
type turnstileResponse struct {
	Success            bool     `json:"success"`
	ErrorCodes         []string `json:"error-codes"`
	Hostname           string   `json:"hostname"`
	ChallengeTimestamp string   `json:"challenge_ts"`
}

func (s *botService) callTurnstileAPI(ctx context.Context, secret, token, remoteIP string) (*turnstileResponse, error) {
	vals := url.Values{
		"secret":   {secret},
		"response": {token},
	}
	if remoteIP != "" {
		vals.Set("remoteip", remoteIP)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, turnstileVerifyURL,
		strings.NewReader(vals.Encode()))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.deps.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result turnstileResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// Aseguramos que botService implementa BotProtectionService en compile-time.
var _ BotProtectionService = (*botService)(nil)

// Aseguramos que botService usa repository.BotProtectionConfig (referencia para evitar unused imports).
var _ = (*repository.BotProtectionConfig)(nil)
