package social

import (
	"context"
	"errors"

	dtoa "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
)

// TokenService handles token issuance for social login.
type TokenService interface {
	// IssueSocialTokens issues access and refresh tokens after social login.
	IssueSocialTokens(ctx context.Context, tenantSlug, clientID, userID string, amr []string) (*dtoa.LoginResponse, error)
}

// Errors for token service.
var (
	ErrTokenIssuerNotConfigured = errors.New("token issuer not configured")
	ErrTokenIssueFailed         = errors.New("token issuance failed")
	ErrRefreshStoreFailed       = errors.New("refresh token storage failed")
)
