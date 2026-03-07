package social

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// StartDeps contains dependencies for start service.
type StartDeps struct {
	StateSigner  StateSigner         // Interface to sign state JWTs
	Registry     *Registry           // Provider registry (replaces OIDCFactory)
	GenericOIDC  GenericOIDCResolver // Generic OIDC alias resolver
	ClientConfig ClientConfigService // Client configuration validation
}

// startService implements StartService.
type startService struct {
	stateSigner  StateSigner
	registry     *Registry
	genericOIDC  GenericOIDCResolver
	clientConfig ClientConfigService
}

// NewStartService creates a new StartService.
func NewStartService(d StartDeps) StartService {
	return &startService{
		stateSigner:  d.StateSigner,
		registry:     d.Registry,
		genericOIDC:  d.GenericOIDC,
		clientConfig: d.ClientConfig,
	}
}

// Start initiates social login flow and returns the redirect URL.
func (s *startService) Start(ctx context.Context, req StartRequest) (*StartResult, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("social.start"))

	// Validate required fields
	if req.TenantSlug == "" {
		return nil, ErrStartMissingTenant
	}
	if req.ClientID == "" {
		return nil, ErrStartMissingClientID
	}
	if req.Provider == "" {
		return nil, ErrStartProviderUnknown
	}

	// Validate client exists and provider is allowed using ClientConfigService.
	if s.clientConfig == nil {
		log.Error("client configuration service not configured")
		return nil, ErrStartProviderDisabled
	}

	// Validate client exists.
	_, err := s.clientConfig.GetClient(ctx, req.TenantSlug, req.ClientID)
	if err != nil {
		if errors.Is(err, ErrClientNotFound) {
			return nil, ErrStartInvalidClient
		}
		log.Error("failed to get client", logger.Err(err))
		return nil, fmt.Errorf("%w: %v", ErrStartInvalidClient, err)
	}

	// Validate provider is allowed for this client.
	if err := s.clientConfig.IsProviderAllowed(ctx, req.TenantSlug, req.ClientID, req.Provider); err != nil {
		if errors.Is(err, ErrProviderMisconfigured) {
			log.Error("provider misconfigured", logger.Err(err))
			return nil, fmt.Errorf("%w: %v", ErrStartProviderMisconfigured, err)
		}
		log.Warn("provider not allowed",
			logger.String("provider", req.Provider),
			logger.TenantID(req.TenantSlug),
			logger.Err(err),
		)
		return nil, ErrStartProviderDisabled
	}

	// Validate redirect_uri if provided.
	if req.RedirectURI != "" {
		if err := s.clientConfig.ValidateRedirectURI(ctx, req.TenantSlug, req.ClientID, req.RedirectURI); err != nil {
			if errors.Is(err, ErrRedirectInvalid) {
				return nil, ErrStartInvalidRedirect
			}
			if errors.Is(err, ErrRedirectNotAllowed) {
				return nil, ErrStartRedirectNotAllowed
			}
			log.Warn("redirect_uri validation failed", logger.Err(err))
			return nil, ErrStartInvalidRedirect
		}
	}

	// Generate nonce for OIDC
	nonce, err := generateNonce(16)
	if err != nil {
		log.Error("failed to generate nonce", logger.Err(err))
		return nil, ErrStartAuthURLFailed
	}

	// Generate signed state JWT if StateSigner is available
	if s.stateSigner == nil {
		log.Error("state signer not configured")
		return nil, ErrStartAuthURLFailed
	}

	state, err := s.stateSigner.SignState(StateClaims{
		Provider:    req.Provider,
		TenantSlug:  req.TenantSlug,
		ClientID:    req.ClientID,
		RedirectURI: req.RedirectURI,
		Nonce:       nonce,
	})
	if err != nil {
		log.Error("failed to sign state", logger.Err(err))
		return nil, ErrStartAuthURLFailed
	}

	// Use Registry for all providers (polymorphic dispatch)
	if s.registry != nil && s.registry.Has(req.Provider) {
		oidc, err := s.registry.Build(ctx, req.Provider, req.TenantSlug, req.BaseURL)
		if err != nil {
			log.Error("failed to create OIDC client",
				logger.String("provider", req.Provider),
				logger.TenantID(req.TenantSlug),
				logger.Err(err),
			)
			return nil, fmt.Errorf("%w: %v", ErrStartAuthURLFailed, err)
		}

		authURL, err := oidc.AuthURL(ctx, state, nonce)
		if err != nil {
			log.Error("failed to build auth URL",
				logger.String("provider", req.Provider),
				logger.Err(err),
			)
			return nil, fmt.Errorf("%w: %v", ErrStartAuthURLFailed, err)
		}

		log.Info("social login started",
			logger.String("provider", req.Provider),
			logger.TenantID(req.TenantSlug),
		)

		return &StartResult{
			RedirectURL: authURL,
		}, nil
	}

	// Resolve custom OIDC aliases (including gitlab when configured via customOidcProviders).
	if s.genericOIDC != nil {
		oidc, err := s.genericOIDC.BuildForAlias(ctx, req.TenantSlug, req.BaseURL, req.Provider)
		if err == nil {
			authURL, err := oidc.AuthURL(ctx, state, nonce)
			if err != nil {
				log.Error("failed to build generic OIDC auth URL",
					logger.String("provider", req.Provider),
					logger.Err(err),
				)
				return nil, fmt.Errorf("%w: %v", ErrStartAuthURLFailed, err)
			}

			log.Info("social login started via generic oidc",
				logger.String("provider", req.Provider),
				logger.TenantID(req.TenantSlug),
			)
			return &StartResult{RedirectURL: authURL}, nil
		}
		log.Debug("generic OIDC alias resolution failed",
			logger.String("provider", req.Provider),
			logger.TenantID(req.TenantSlug),
			logger.Err(err),
		)
	}

	return nil, ErrStartProviderUnknown
}

// generateNonce generates a random base64url-encoded string.
func generateNonce(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
