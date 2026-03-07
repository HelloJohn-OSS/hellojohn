package social

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dtoa "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	"github.com/dropDatabas3/hellojohn/internal/jwt"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// TokenDeps contains dependencies for token service.
type TokenDeps struct {
	DAL        store.DataAccessLayer // V2 data access layer
	Issuer     *jwt.Issuer           // JWT issuer for signing tokens
	BaseURL    string                // Base URL for issuer resolution
	RefreshTTL time.Duration         // TTL for refresh tokens (default 30 days)
}

// tokenService implements TokenService.
type tokenService struct {
	dal        store.DataAccessLayer
	issuer     *jwt.Issuer
	baseURL    string
	refreshTTL time.Duration
}

// NewTokenService creates a new TokenService.
func NewTokenService(d TokenDeps) TokenService {
	ttl := d.RefreshTTL
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour // 30 days default
	}
	return &tokenService{
		dal:        d.DAL,
		issuer:     d.Issuer,
		baseURL:    d.BaseURL,
		refreshTTL: ttl,
	}
}

// IssueSocialTokens issues access and refresh tokens after social login.
func (s *tokenService) IssueSocialTokens(ctx context.Context, tenantSlug, clientID, userID string, amr []string) (*dtoa.LoginResponse, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("social.token"))

	if s.issuer == nil {
		log.Error("issuer not configured")
		return nil, ErrTokenIssuerNotConfigured
	}

	// Get tenant data access via DAL
	if s.dal == nil {
		log.Error("DAL not configured")
		return nil, ErrTokenIssuerNotConfigured
	}

	tda, err := s.dal.ForTenant(ctx, tenantSlug)
	if err != nil {
		log.Error("tenant not found", logger.Err(err), logger.TenantID(tenantSlug))
		return nil, fmt.Errorf("%w: tenant not found", ErrTokenIssueFailed)
	}

	settings := tda.Settings()
	if settings == nil {
		log.Error("tenant settings not available", logger.TenantID(tenantSlug))
		return nil, fmt.Errorf("%w: tenant settings not found", ErrTokenIssueFailed)
	}

	// Resolve effective issuer for tenant
	issMode := settings.IssuerMode
	issOverride := settings.IssuerOverride
	effectiveIss := jwt.ResolveIssuer(s.baseURL, issMode, tenantSlug, issOverride)

	// Build standard claims
	stdClaims := map[string]any{
		"tid": tenantSlug,
		"cid": clientID,
	}
	if len(amr) > 0 {
		stdClaims["amr"] = amr
	}

	// Issue access token for tenant
	accessToken, exp, err := s.issuer.IssueAccessForTenant(tenantSlug, effectiveIss, userID, clientID, stdClaims, nil)
	if err != nil {
		log.Error("failed to issue access token", logger.Err(err))
		return nil, fmt.Errorf("%w: access token: %v", ErrTokenIssueFailed, err)
	}

	// Generate refresh token (opaque)
	refreshToken, err := generateOpaqueToken(32)
	if err != nil {
		log.Error("failed to generate refresh token", logger.Err(err))
		return nil, fmt.Errorf("%w: refresh token generation", ErrTokenIssueFailed)
	}

	// Store refresh token in tenant DB through DAL repositories.
	if err := s.storeRefreshToken(ctx, tda, userID, clientID, refreshToken); err != nil {
		log.Error("failed to store refresh token", logger.Err(err), logger.TenantID(tenantSlug))
		return nil, fmt.Errorf("%w: %v", ErrTokenIssueFailed, err)
	}

	// Calculate expires_in from exp
	expiresIn := int64(time.Until(exp).Seconds())
	if expiresIn < 0 {
		expiresIn = 900 // 15 minutes default
	}

	log.Info("social tokens issued",
		logger.TenantID(tenantSlug),
		logger.Int("expires_in", int(expiresIn)),
	)

	return &dtoa.LoginResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
	}, nil
}

// storeRefreshToken stores refresh token hash in tenant DB.
func (s *tokenService) storeRefreshToken(ctx context.Context, tda store.TenantDataAccess, userID, clientID, refreshToken string) error {
	if tda == nil {
		return fmt.Errorf("%w: tenant data access unavailable", ErrRefreshStoreFailed)
	}
	if err := tda.RequireDB(); err != nil {
		return fmt.Errorf("%w: %v", ErrRefreshStoreFailed, err)
	}
	tokens := tda.Tokens()
	if tokens == nil {
		return fmt.Errorf("%w: token repository unavailable", ErrRefreshStoreFailed)
	}

	ttlSeconds := int(s.refreshTTL.Seconds())
	if ttlSeconds <= 0 {
		ttlSeconds = int((30 * 24 * time.Hour).Seconds())
	}

	_, err := tokens.Create(ctx, repository.CreateRefreshTokenInput{
		TenantID:   tda.ID(),
		ClientID:   clientID,
		UserID:     userID,
		TokenHash:  sha256Base64(refreshToken),
		TTLSeconds: ttlSeconds,
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRefreshStoreFailed, err)
	}

	return nil
}

// generateOpaqueToken generates a cryptographically secure opaque token.
func generateOpaqueToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// sha256Base64 returns base64url encoded SHA256 hash.
func sha256Base64(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
