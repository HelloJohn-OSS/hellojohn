package auth

import (
	"context"
	"net/url"
	"sort"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	"go.uber.org/zap"
)

// ProvidersService defines operations for providers discovery.
type ProvidersService interface {
	GetProviders(ctx context.Context, in dto.ProvidersRequest) (*dto.ProvidersResult, error)
}

// ProviderConfig holds optional global provider configuration.
// JWTIssuer is only used to derive a default redirect_uri when not provided.
type ProviderConfig struct {
	JWTIssuer string
}

// ProvidersDeps contains dependencies for the providers service.
type ProvidersDeps struct {
	DAL       store.DataAccessLayer
	Providers ProviderConfig
}

type providersService struct {
	deps ProvidersDeps
}

// NewProvidersService creates a new ProvidersService.
func NewProvidersService(deps ProvidersDeps) ProvidersService {
	return &providersService{deps: deps}
}

// GetProviders returns available auth providers based on real tenant/client configuration.
func (s *providersService) GetProviders(ctx context.Context, in dto.ProvidersRequest) (*dto.ProvidersResult, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("auth.providers"),
		logger.Op("GetProviders"),
	)

	result := &dto.ProvidersResult{
		Providers: make([]dto.ProviderInfo, 0, 10),
	}

	tenantID := strings.TrimSpace(in.TenantID)
	clientID := strings.TrimSpace(in.ClientID)
	redirectURI := strings.TrimSpace(in.RedirectURI)

	var (
		tenantSlug string
		settings   *repository.TenantSettings
		client     *repository.Client
	)

	if tenantID != "" {
		tda, err := s.deps.DAL.ForTenant(ctx, tenantID)
		if err != nil {
			log.Warn("tenant not found for providers lookup", zap.String("tenant_id", tenantID), logger.Err(err))
		} else if tda != nil {
			tenantSlug = tda.Slug()
			settings = tda.Settings()
			if clientID != "" {
				c, err := tda.Clients().Get(ctx, clientID)
				if err != nil || c == nil {
					log.Warn("client not found for providers lookup",
						zap.String("tenant_slug", tenantSlug),
						zap.String("client_id", clientID),
					)
				} else {
					client = c
				}
			}
		}
	}

	passwordEnabled := true
	if client != nil && len(client.Providers) > 0 {
		passwordEnabled = hasProvider(client.Providers, "password")
	}

	passwordInfo := dto.ProviderInfo{
		Name:    "password",
		Enabled: passwordEnabled,
		Ready:   passwordEnabled,
		Popup:   false,
	}
	if !passwordEnabled {
		passwordInfo.Reason = "password provider not enabled for this client"
	}
	result.Providers = append(result.Providers, passwordInfo)

	var socialCfg *repository.SocialConfig
	if settings != nil {
		socialCfg = settings.SocialProviders
	}

	providerNames := resolveProviderNames(client, socialCfg)
	sort.Strings(providerNames)

	for _, providerName := range providerNames {
		ready, reason := providerReady(providerName, socialCfg)
		info := dto.ProviderInfo{
			Name:    providerName,
			Enabled: true,
			Ready:   ready,
			Popup:   true,
		}
		if !ready {
			info.Reason = reason
		}

		if ready && tenantSlug != "" && client != nil && clientID != "" {
			if startURL := s.buildStartURL(providerName, tenantSlug, clientID, redirectURI, client); startURL != "" {
				info.StartURL = &startURL
			}
		}

		result.Providers = append(result.Providers, info)
	}

	log.Debug("providers resolved", zap.Int("count", len(result.Providers)))
	return result, nil
}

func (s *providersService) buildStartURL(provider, tenantSlug, clientID, redirectURI string, client *repository.Client) string {
	if tenantSlug == "" || clientID == "" || client == nil {
		return ""
	}

	redirect := strings.TrimSpace(redirectURI)
	if redirect == "" {
		base := strings.TrimRight(strings.TrimSpace(s.deps.Providers.JWTIssuer), "/")
		if base != "" {
			redirect = base + "/v2/auth/social/result"
		}
	}
	if redirect == "" {
		return ""
	}
	if !redirectAllowed(client, redirect) {
		return ""
	}

	values := url.Values{}
	values.Set("tenant_id", tenantSlug)
	values.Set("client_id", clientID)
	values.Set("redirect_uri", redirect)

	return "/v2/auth/social/" + url.PathEscape(provider) + "/start?" + values.Encode()
}

func resolveProviderNames(client *repository.Client, cfg *repository.SocialConfig) []string {
	if cfg == nil {
		return nil
	}

	seen := make(map[string]struct{})
	var providers []string
	add := func(name string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || name == "password" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		providers = append(providers, name)
	}

	if client != nil && len(client.Providers) > 0 {
		for _, provider := range client.Providers {
			if providerEnabledInConfig(provider, cfg) {
				add(provider)
			}
		}
		return providers
	}

	if cfg.GoogleEnabled {
		add("google")
	}
	if cfg.GitHubEnabled {
		add("github")
	}
	if cfg.FacebookEnabled {
		add("facebook")
	}
	if cfg.DiscordEnabled {
		add("discord")
	}
	if cfg.MicrosoftEnabled {
		add("microsoft")
	}
	if cfg.LinkedInEnabled {
		add("linkedin")
	}
	if cfg.AppleEnabled {
		add("apple")
	}
	for _, custom := range cfg.CustomOIDCProviders {
		if custom.Enabled {
			add(custom.Alias)
		}
	}

	return providers
}

func providerEnabledInConfig(provider string, cfg *repository.SocialConfig) bool {
	if cfg == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "google":
		return cfg.GoogleEnabled
	case "github":
		return cfg.GitHubEnabled
	case "facebook":
		return cfg.FacebookEnabled
	case "discord":
		return cfg.DiscordEnabled
	case "microsoft":
		return cfg.MicrosoftEnabled
	case "linkedin":
		return cfg.LinkedInEnabled
	case "apple":
		return cfg.AppleEnabled
	default:
		for _, custom := range cfg.CustomOIDCProviders {
			if strings.EqualFold(custom.Alias, provider) {
				return custom.Enabled
			}
		}
		return false
	}
}

func providerReady(provider string, cfg *repository.SocialConfig) (bool, string) {
	if cfg == nil {
		return false, "social providers not configured"
	}

	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "google":
		if !cfg.GoogleEnabled {
			return false, "provider disabled"
		}
		if strings.TrimSpace(cfg.GoogleClient) == "" || !hasSecret(cfg.GoogleSecret, cfg.GoogleSecretEnc) {
			return false, "google client_id/client_secret missing"
		}
		return true, ""
	case "github":
		if !cfg.GitHubEnabled {
			return false, "provider disabled"
		}
		if strings.TrimSpace(cfg.GitHubClient) == "" || !hasSecret(cfg.GitHubSecret, cfg.GitHubSecretEnc) {
			return false, "github client_id/client_secret missing"
		}
		return true, ""
	case "facebook":
		if !cfg.FacebookEnabled {
			return false, "provider disabled"
		}
		if strings.TrimSpace(cfg.FacebookClient) == "" || !hasSecret(cfg.FacebookSecret, cfg.FacebookSecretEnc) {
			return false, "facebook client_id/client_secret missing"
		}
		return true, ""
	case "discord":
		if !cfg.DiscordEnabled {
			return false, "provider disabled"
		}
		if strings.TrimSpace(cfg.DiscordClient) == "" || !hasSecret(cfg.DiscordSecret, cfg.DiscordSecretEnc) {
			return false, "discord client_id/client_secret missing"
		}
		return true, ""
	case "microsoft":
		if !cfg.MicrosoftEnabled {
			return false, "provider disabled"
		}
		if strings.TrimSpace(cfg.MicrosoftClient) == "" || !hasSecret(cfg.MicrosoftSecret, cfg.MicrosoftSecretEnc) {
			return false, "microsoft client_id/client_secret missing"
		}
		return true, ""
	case "linkedin":
		if !cfg.LinkedInEnabled {
			return false, "provider disabled"
		}
		if strings.TrimSpace(cfg.LinkedInClient) == "" || !hasSecret(cfg.LinkedInSecret, cfg.LinkedInSecretEnc) {
			return false, "linkedin client_id/client_secret missing"
		}
		return true, ""
	case "apple":
		if !cfg.AppleEnabled {
			return false, "provider disabled"
		}
		if strings.TrimSpace(cfg.AppleClientID) == "" ||
			strings.TrimSpace(cfg.AppleTeamID) == "" ||
			strings.TrimSpace(cfg.AppleKeyID) == "" ||
			strings.TrimSpace(cfg.ApplePrivateKeyEnc) == "" {
			return false, "apple client/team/key/private_key missing"
		}
		return true, ""
	default:
		for _, custom := range cfg.CustomOIDCProviders {
			if !strings.EqualFold(custom.Alias, provider) {
				continue
			}
			if !custom.Enabled {
				return false, "provider disabled"
			}
			if strings.TrimSpace(custom.WellKnownURL) == "" ||
				strings.TrimSpace(custom.ClientID) == "" ||
				strings.TrimSpace(custom.ClientSecretEnc) == "" {
				return false, "custom oidc wellKnownUrl/clientId/clientSecret missing"
			}
			return true, ""
		}
		return false, "provider not configured"
	}
}

func redirectAllowed(client *repository.Client, redirectURI string) bool {
	canonicalRedirect, ok := canonicalizeRedirectURI(redirectURI)
	if !ok {
		return false
	}

	for _, allowed := range client.RedirectURIs {
		canonicalAllowed, ok := canonicalizeRedirectURI(allowed)
		if !ok {
			continue
		}
		if canonicalAllowed == canonicalRedirect {
			return true
		}
	}
	return false
}

func hasSecret(plain, encrypted string) bool {
	return strings.TrimSpace(plain) != "" || strings.TrimSpace(encrypted) != ""
}

func hasProvider(providers []string, expected string) bool {
	for _, provider := range providers {
		if strings.EqualFold(strings.TrimSpace(provider), expected) {
			return true
		}
	}
	return false
}

func canonicalizeRedirectURI(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "*") {
		return "", false
	}

	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return "", false
	}
	if u.Fragment != "" {
		return "", false
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if scheme != "https" {
		if scheme != "http" || !(host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]" || strings.HasPrefix(host, "127.")) {
			return "", false
		}
	}

	u.Scheme = scheme
	u.Host = strings.ToLower(u.Host)
	if u.Path == "" {
		u.Path = "/"
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		u.Host = u.Hostname()
	}
	u.Fragment = ""
	return u.String(), true
}
