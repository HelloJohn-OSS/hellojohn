package social

import (
	"context"
	"errors"
)

// ProvisioningService handles user provisioning for social login.
type ProvisioningService interface {
	// EnsureUserAndIdentity creates or updates a user from social login claims.
	// Returns the user ID on success.
	EnsureUserAndIdentity(ctx context.Context, tenantSlug, provider string, claims *OIDCClaims) (userID string, err error)
}

// Errors for provisioning service.
var (
	ErrProvisioningEmailMissing = errors.New("email missing from claims")
	ErrProvisioningDBRequired   = errors.New("tenant database required")
	ErrProvisioningFailed       = errors.New("user provisioning failed")
	ErrProvisioningIdentity     = errors.New("identity linking failed")
)
