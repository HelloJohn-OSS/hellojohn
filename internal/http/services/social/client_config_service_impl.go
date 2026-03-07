package social

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// ClientConfigDeps contains dependencies for client config service.
type ClientConfigDeps struct {
	TenantProvider TenantProvider
}

// clientConfigService implements ClientConfigService.
type clientConfigService struct {
	tenantProvider TenantProvider
}

// NewClientConfigService creates a new ClientConfigService.
func NewClientConfigService(d ClientConfigDeps) ClientConfigService {
	return &clientConfigService{
		tenantProvider: d.TenantProvider,
	}
}

// GetClient returns the client configuration for a tenant/clientID pair.
func (s *clientConfigService) GetClient(ctx context.Context, tenantSlug, clientID string) (*repository.Client, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("social.clientconfig"))

	if tenantSlug == "" {
		return nil, ErrTenantRequired
	}
	if clientID == "" {
		return nil, ErrClientRequired
	}

	client, err := s.tenantProvider.GetClient(ctx, tenantSlug, clientID)
	if err != nil {
		log.Warn("client not found", logger.TenantID(tenantSlug), logger.String("client_id", clientID), logger.Err(err))
		return nil, ErrClientNotFound
	}
	return client, nil
}

// ValidateRedirectURI validates that a redirect URI is allowed for a client.
func (s *clientConfigService) ValidateRedirectURI(ctx context.Context, tenantSlug, clientID, redirectURI string) error {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("social.clientconfig"))

	if redirectURI == "" {
		return nil // Empty redirect is allowed (optional param)
	}

	client, err := s.GetClient(ctx, tenantSlug, clientID)
	if err != nil {
		return err
	}

	// Canonicalize the input URI
	canonical, err := canonicalizeRedirect(redirectURI)
	if err != nil {
		log.Warn("redirect_uri invalid", logger.Err(err))
		return fmt.Errorf("%w: %v", ErrRedirectInvalid, err)
	}

	// Check against allowlist
	for _, allowed := range client.RedirectURIs {
		allowedCanonical, err := canonicalizeRedirect(allowed)
		if err != nil {
			continue // Skip malformed entries
		}
		if canonical == allowedCanonical {
			return nil // Match found
		}
	}

	log.Warn("redirect_uri not allowed",
		logger.TenantID(tenantSlug),
		logger.String("client_id", clientID),
	)
	return ErrRedirectNotAllowed
}

// IsProviderAllowed checks if a social provider is allowed for a client.
func (s *clientConfigService) IsProviderAllowed(ctx context.Context, tenantSlug, clientID, provider string) error {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("social.clientconfig"))

	if tenantSlug == "" {
		return ErrTenantRequired
	}

	tenant, err := s.tenantProvider.GetTenant(ctx, tenantSlug)
	if err != nil {
		return fmt.Errorf("%w: tenant not found", ErrTenantRequired)
	}

	// Check global social login enabled
	if !tenant.Settings.SocialLoginEnabled {
		log.Warn("social login disabled for tenant", logger.TenantID(tenantSlug))
		return ErrSocialLoginDisabled
	}

	// Get client
	client, err := s.GetClient(ctx, tenantSlug, clientID)
	if err != nil {
		return err
	}

	// Check provider in client.Providers list
	providerFound := false
	for _, p := range client.Providers {
		if strings.EqualFold(p, provider) {
			providerFound = true
			break
		}
	}
	if !providerFound {
		log.Warn("provider not in client.Providers",
			logger.String("provider", provider),
			logger.TenantID(tenantSlug),
			logger.String("client_id", clientID),
		)
		return ErrProviderNotAllowed
	}

	// Get effective social config from tenant (no per-client override)
	cfg := tenant.Settings.SocialProviders

	// Validate provider-specific config
	switch strings.ToLower(provider) {
	case "google":
		if err := validateStandardProvider(cfg != nil && cfg.GoogleEnabled, cfg.GoogleClient, cfg.GoogleSecret, cfg.GoogleSecretEnc); err != nil {
			log.Warn("google provider config invalid", logger.Err(err), logger.TenantID(tenantSlug), logger.String("client_id", clientID))
			return err
		}
	case "github":
		if err := validateStandardProvider(cfg != nil && cfg.GitHubEnabled, cfg.GitHubClient, cfg.GitHubSecret, cfg.GitHubSecretEnc); err != nil {
			log.Warn("github provider config invalid", logger.Err(err), logger.TenantID(tenantSlug), logger.String("client_id", clientID))
			return err
		}
	case "facebook":
		if err := validateStandardProvider(cfg != nil && cfg.FacebookEnabled, cfg.FacebookClient, cfg.FacebookSecret, cfg.FacebookSecretEnc); err != nil {
			log.Warn("facebook provider config invalid", logger.Err(err), logger.TenantID(tenantSlug), logger.String("client_id", clientID))
			return err
		}
	case "discord":
		if err := validateStandardProvider(cfg != nil && cfg.DiscordEnabled, cfg.DiscordClient, cfg.DiscordSecret, cfg.DiscordSecretEnc); err != nil {
			log.Warn("discord provider config invalid", logger.Err(err), logger.TenantID(tenantSlug), logger.String("client_id", clientID))
			return err
		}
	case "microsoft":
		if err := validateStandardProvider(cfg != nil && cfg.MicrosoftEnabled, cfg.MicrosoftClient, cfg.MicrosoftSecret, cfg.MicrosoftSecretEnc); err != nil {
			log.Warn("microsoft provider config invalid", logger.Err(err), logger.TenantID(tenantSlug), logger.String("client_id", clientID))
			return err
		}
	case "linkedin":
		if err := validateStandardProvider(cfg != nil && cfg.LinkedInEnabled, cfg.LinkedInClient, cfg.LinkedInSecret, cfg.LinkedInSecretEnc); err != nil {
			log.Warn("linkedin provider config invalid", logger.Err(err), logger.TenantID(tenantSlug), logger.String("client_id", clientID))
			return err
		}
	case "apple":
		if cfg == nil || !cfg.AppleEnabled {
			log.Warn("apple not enabled in social config", logger.TenantID(tenantSlug), logger.String("client_id", clientID))
			return ErrProviderNotAllowed
		}
		if strings.TrimSpace(cfg.AppleClientID) == "" ||
			strings.TrimSpace(cfg.AppleTeamID) == "" ||
			strings.TrimSpace(cfg.AppleKeyID) == "" ||
			strings.TrimSpace(cfg.ApplePrivateKeyEnc) == "" {
			log.Error("apple misconfigured (missing required fields)", logger.TenantID(tenantSlug), logger.String("client_id", clientID))
			return ErrProviderMisconfigured
		}
	case "gitlab":
		if err := validateCustomOIDCProvider(cfg, "gitlab"); err != nil {
			log.Warn("gitlab provider config invalid", logger.Err(err), logger.TenantID(tenantSlug), logger.String("client_id", clientID))
			return err
		}
	default:
		if err := validateCustomOIDCProvider(cfg, provider); err != nil {
			log.Warn("unknown/disabled provider", logger.String("provider", provider), logger.Err(err))
			return err
		}
	}

	return nil
}

// GetSocialConfig returns the effective social config for a client.
func (s *clientConfigService) GetSocialConfig(ctx context.Context, tenantSlug, clientID string) (*repository.SocialConfig, error) {
	tenant, err := s.tenantProvider.GetTenant(ctx, tenantSlug)
	if err != nil {
		return nil, fmt.Errorf("%w: tenant not found", ErrTenantRequired)
	}

	// Validate client exists
	_, err = s.GetClient(ctx, tenantSlug, clientID)
	if err != nil {
		return nil, err
	}

	// Social config always comes from the tenant (no per-client override)
	return tenant.Settings.SocialProviders, nil
}

// canonicalizeRedirect canonicalizes a redirect URI for comparison.
func canonicalizeRedirect(uri string) (string, error) {
	if uri == "" {
		return "", fmt.Errorf("empty URI")
	}

	u, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// Must be absolute URL
	if !u.IsAbs() {
		return "", fmt.Errorf("must be absolute URL")
	}

	// Fragment prohibited
	if u.Fragment != "" {
		return "", fmt.Errorf("fragment not allowed")
	}

	// Scheme must be http or https
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("scheme must be http or https")
	}

	// Require https except for localhost
	host := strings.ToLower(u.Hostname())
	if scheme == "http" && !isLocalhost(host) {
		return "", fmt.Errorf("https required for non-localhost")
	}

	// Normalize host to lowercase
	u.Host = strings.ToLower(u.Host)
	u.Scheme = scheme

	// Normalize empty path to "/"
	if u.Path == "" {
		u.Path = "/"
	}

	// Remove default ports
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		u.Host = u.Hostname()
	}

	// Rebuild canonical string (preserves query, removes fragment)
	u.Fragment = ""
	return u.String(), nil
}

// isLocalhost checks if a host is localhost or loopback.
func isLocalhost(host string) bool {
	host = strings.ToLower(host)
	return host == "localhost" ||
		host == "127.0.0.1" ||
		host == "::1" ||
		host == "[::1]" ||
		strings.HasPrefix(host, "127.")
}

func validateStandardProvider(enabled bool, clientID, plainSecret, encSecret string) error {
	if !enabled {
		return ErrProviderNotAllowed
	}
	if strings.TrimSpace(clientID) == "" {
		return ErrProviderMisconfigured
	}
	if strings.TrimSpace(plainSecret) == "" && strings.TrimSpace(encSecret) == "" {
		return ErrProviderMisconfigured
	}
	return nil
}

func validateCustomOIDCProvider(cfg *repository.SocialConfig, alias string) error {
	if cfg == nil {
		return ErrProviderNotAllowed
	}
	for _, custom := range cfg.CustomOIDCProviders {
		if !strings.EqualFold(custom.Alias, alias) {
			continue
		}
		if !custom.Enabled {
			return ErrProviderNotAllowed
		}
		if strings.TrimSpace(custom.WellKnownURL) == "" ||
			strings.TrimSpace(custom.ClientID) == "" ||
			strings.TrimSpace(custom.ClientSecretEnc) == "" {
			return ErrProviderMisconfigured
		}
		return nil
	}
	return ErrProviderNotAllowed
}
