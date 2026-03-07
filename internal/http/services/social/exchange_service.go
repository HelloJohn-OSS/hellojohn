package social

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/social"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"go.uber.org/zap"
)

// Cache defines the cache interface for social code storage.
type Cache interface {
	Get(key string) ([]byte, bool)
	Delete(key string) error
}

// ExchangeService defines operations for social code exchange.
type ExchangeService interface {
	Exchange(ctx context.Context, req dto.ExchangeRequest) (*dto.ExchangePayload, error)
}

// ExchangeDeps contains dependencies for the exchange service.
type ExchangeDeps struct {
	Cache        Cache
	ClientConfig ClientConfigService // For hardened validation
}

type exchangeService struct {
	cache        Cache
	clientConfig ClientConfigService
}

// NewExchangeService creates a new ExchangeService.
func NewExchangeService(deps ExchangeDeps) ExchangeService {
	return &exchangeService{
		cache:        deps.Cache,
		clientConfig: deps.ClientConfig,
	}
}

// Service errors
var (
	ErrCodeMissing                   = fmt.Errorf("code is required")
	ErrClientMissing                 = fmt.Errorf("client_id is required")
	ErrCodeNotFound                  = fmt.Errorf("code not found or expired")
	ErrPayloadInvalid                = fmt.Errorf("stored payload is invalid")
	ErrClientMismatch                = fmt.Errorf("client_id does not match")
	ErrTenantMismatch                = fmt.Errorf("tenant_id does not match")
	ErrExchangeTenantInvalid         = fmt.Errorf("tenant not found")
	ErrExchangeProviderNotAllowed    = fmt.Errorf("provider not allowed")
	ErrExchangeProviderMisconfigured = fmt.Errorf("provider misconfigured")
)

// Exchange exchanges a social login code for tokens.
// This is a one-shot operation: the code is deleted after successful exchange.
func (s *exchangeService) Exchange(ctx context.Context, req dto.ExchangeRequest) (*dto.ExchangePayload, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("social.exchange"),
		logger.Op("Exchange"),
	)

	// Validate input
	code := strings.TrimSpace(req.Code)
	clientID := strings.TrimSpace(req.ClientID)
	tenantID := strings.TrimSpace(req.TenantID)

	if code == "" {
		return nil, ErrCodeMissing
	}
	if clientID == "" {
		return nil, ErrClientMissing
	}

	// Get from cache
	key := "social:code:" + code
	payload, ok := s.cache.Get(key)
	if !ok || len(payload) == 0 {
		log.Debug("code not found", zap.String("key_prefix", "social:code:"))
		return nil, ErrCodeNotFound
	}

	// Parse stored payload
	var stored dto.ExchangePayload
	if err := json.Unmarshal(payload, &stored); err != nil {
		log.Error("failed to unmarshal payload", logger.Err(err))
		return nil, ErrPayloadInvalid
	}

	// Validate client_id (case-insensitive, trimmed)
	storedClientID := strings.TrimSpace(stored.ClientID)
	if !strings.EqualFold(storedClientID, clientID) {
		log.Debug("client_id mismatch",
			zap.String("expected", storedClientID),
			zap.String("got", clientID),
		)
		return nil, ErrClientMismatch
	}

	// Validate tenant_id if provided
	if tenantID != "" {
		storedTenantID := strings.TrimSpace(stored.TenantID)
		storedTenantSlug := strings.TrimSpace(stored.TenantSlug)
		if !strings.EqualFold(storedTenantID, tenantID) && !strings.EqualFold(storedTenantSlug, tenantID) {
			log.Debug("tenant_id mismatch",
				zap.String("expected", storedTenantID),
				zap.String("got", tenantID),
			)
			return nil, ErrTenantMismatch
		}
	}

	// Hardened validation using ClientConfigService (if available)
	if s.clientConfig != nil {
		// Validate required payload fields
		if stored.TenantSlug == "" {
			log.Warn("payload missing tenant_slug")
			return nil, ErrPayloadInvalid
		}
		if stored.Provider == "" {
			log.Warn("payload missing provider")
			return nil, ErrPayloadInvalid
		}

		// Validate client exists in control plane
		if _, err := s.clientConfig.GetClient(ctx, stored.TenantSlug, stored.ClientID); err != nil {
			if errors.Is(err, ErrClientNotFound) {
				log.Warn("client not found in control plane",
					logger.TenantID(stored.TenantSlug),
					logger.String("client_id", stored.ClientID),
				)
				return nil, ErrClientMismatch
			}
			log.Error("failed to get client", logger.Err(err))
			return nil, ErrExchangeTenantInvalid
		}

		// Validate provider is allowed
		if err := s.clientConfig.IsProviderAllowed(ctx, stored.TenantSlug, stored.ClientID, stored.Provider); err != nil {
			if errors.Is(err, ErrProviderMisconfigured) {
				log.Error("provider misconfigured", logger.Err(err))
				return nil, ErrExchangeProviderMisconfigured
			}
			if errors.Is(err, ErrSocialLoginDisabled) {
				log.Warn("social login disabled", logger.TenantID(stored.TenantSlug))
				return nil, ErrExchangeProviderNotAllowed
			}
			log.Warn("provider not allowed",
				logger.String("provider", stored.Provider),
				logger.TenantID(stored.TenantSlug),
				logger.Err(err),
			)
			return nil, ErrExchangeProviderNotAllowed
		}

		log.Debug("hardened validation passed",
			logger.TenantID(stored.TenantSlug),
			logger.String("provider", stored.Provider),
		)
	}

	// Delete from cache (one-shot) after successful validation
	if err := s.cache.Delete(key); err != nil {
		log.Debug("failed to delete code from cache", logger.Err(err))
		// Don't fail the exchange, log and continue
	}

	log.Debug("social code exchanged successfully")
	return &stored, nil
}
