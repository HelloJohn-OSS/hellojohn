package oauth

import (
	"context"
	"fmt"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	"go.uber.org/zap"
)

// RevokeService defines operations for token revocation.
type RevokeService interface {
	Revoke(ctx context.Context, token string) error
}

// RevokeDeps contains dependencies for the revoke service.
type RevokeDeps struct {
	DAL store.DataAccessLayer
}

type revokeService struct {
	deps RevokeDeps
}

// NewRevokeService creates a new RevokeService.
func NewRevokeService(deps RevokeDeps) RevokeService {
	return &revokeService{deps: deps}
}

// Service errors
var (
	ErrRevokeTokenEmpty = fmt.Errorf("token is empty")
)

// Revoke revokes a refresh token if it exists.
// This operation is idempotent: always returns success even if token doesn't exist.
func (s *revokeService) Revoke(ctx context.Context, token string) error {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("oauth.revoke"),
		logger.Op("Revoke"),
	)

	if token == "" {
		return ErrRevokeTokenEmpty
	}

	// Calculate hash (same format as how refresh tokens are stored)
	hash := tokens.SHA256Base64URL(token)

	// Try to get the refresh token by hash (using global access)
	// Note: We need to search across tenants for the token
	// For now, we'll use the ConfigAccess to list tenants and search
	tenants, err := s.deps.DAL.ConfigAccess().Tenants().List(ctx)
	if err != nil {
		log.Debug("failed to list tenants", logger.Err(err))
		// Don't leak info - return success
		return nil
	}

	// Search for the token in each tenant
	for _, t := range tenants {
		tda, err := s.deps.DAL.ForTenant(ctx, t.Slug)
		if err != nil {
			continue
		}

		// Skip tenants without DB
		if tda.RequireDB() != nil {
			continue
		}

		// Try to find and revoke the token
		if s.tryRevokeInTenant(ctx, tda, hash, log) {
			return nil
		}
	}

	// Token not found in any tenant - still return success (idempotent)
	log.Debug("token not found in any tenant (idempotent success)", zap.String("hash_prefix", hash[:8]))
	return nil
}

// tryRevokeInTenant attempts to revoke a token in a specific tenant.
func (s *revokeService) tryRevokeInTenant(ctx context.Context, tda store.TenantDataAccess, hash string, log *zap.Logger) bool {
	rt, err := tda.Tokens().GetByHash(ctx, hash)
	if err != nil {
		if err == repository.ErrNotFound {
			return false
		}
		// Log unexpected errors but don't leak info
		log.Debug("error looking up token", logger.Err(err))
		return false
	}

	if rt == nil {
		return false
	}

	// Found the token - revoke it
	if err := tda.Tokens().Revoke(ctx, rt.ID); err != nil {
		log.Debug("error revoking token", logger.Err(err), zap.String("token_id", rt.ID))
		// Still return "found" so we don't keep searching
		return true
	}

	log.Info("token revoked", zap.String("token_id", rt.ID))
	return true
}
