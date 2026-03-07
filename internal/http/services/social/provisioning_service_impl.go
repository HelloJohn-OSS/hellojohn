package social

import (
	"context"
	"fmt"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// ProvisioningDeps contains dependencies for provisioning service.
type ProvisioningDeps struct {
	DAL store.DataAccessLayer // V2 data access layer
}

// provisioningService implements ProvisioningService.
type provisioningService struct {
	dal store.DataAccessLayer
}

// NewProvisioningService creates a new ProvisioningService.
func NewProvisioningService(d ProvisioningDeps) ProvisioningService {
	return &provisioningService{dal: d.DAL}
}

// EnsureUserAndIdentity creates or updates a user from social login claims.
func (s *provisioningService) EnsureUserAndIdentity(ctx context.Context, tenantSlug, provider string, claims *OIDCClaims) (string, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("social.provisioning"))

	// Validate email
	if claims == nil || strings.TrimSpace(claims.Email) == "" {
		return "", ErrProvisioningEmailMissing
	}
	if strings.TrimSpace(claims.Sub) == "" {
		return "", ErrProvisioningIdentity
	}

	// Get tenant data access via DAL
	if s.dal == nil {
		log.Error("DAL not configured")
		return "", ErrProvisioningDBRequired
	}

	tda, err := s.dal.ForTenant(ctx, tenantSlug)
	if err != nil {
		log.Error("tenant not found", logger.Err(err), logger.TenantID(tenantSlug))
		return "", fmt.Errorf("%w: tenant not found", ErrProvisioningDBRequired)
	}

	if err := tda.RequireDB(); err != nil {
		log.Error("tenant database is required", logger.TenantID(tenantSlug), logger.Err(err))
		return "", fmt.Errorf("%w: no database for tenant", ErrProvisioningDBRequired)
	}

	identities := tda.Identities()
	if identities == nil {
		log.Error("identity repository unavailable", logger.TenantID(tenantSlug))
		return "", fmt.Errorf("%w: identity repository unavailable", ErrProvisioningDBRequired)
	}
	providerName := strings.ToLower(strings.TrimSpace(provider))
	if providerName == "" {
		return "", ErrProvisioningIdentity
	}

	upsertInput := repository.UpsertSocialIdentityInput{
		TenantID:       tda.ID(),
		Provider:       providerName,
		ProviderUserID: strings.TrimSpace(claims.Sub),
		Email:          strings.TrimSpace(claims.Email),
		EmailVerified:  claims.EmailVerified,
		Name:           resolveDisplayName(claims),
		Picture:        strings.TrimSpace(claims.Picture),
		RawClaims: map[string]any{
			"email":          strings.TrimSpace(claims.Email),
			"email_verified": claims.EmailVerified,
			"name":           resolveDisplayName(claims),
			"given_name":     strings.TrimSpace(claims.GivenName),
			"family_name":    strings.TrimSpace(claims.FamilyName),
			"picture":        strings.TrimSpace(claims.Picture),
			"locale":         strings.TrimSpace(claims.Locale),
		},
	}

	userID, isNew, err := identities.Upsert(ctx, upsertInput)
	if err != nil {
		log.Error("identity upsert failed",
			logger.String("provider", provider),
			logger.TenantID(tenantSlug),
			logger.Err(err),
		)
		return "", fmt.Errorf("%w: %v", ErrProvisioningIdentity, err)
	}

	if claims.EmailVerified {
		users := tda.Users()
		if users == nil {
			log.Warn("user repository unavailable for verification update", logger.TenantID(tenantSlug))
		} else if err := users.SetEmailVerified(ctx, userID, true); err != nil {
			log.Warn("failed to update email verification flag",
				logger.TenantID(tenantSlug),
				logger.String("provider", providerName),
				logger.Err(err),
			)
		}
	}

	log.Info("social user provisioned",
		logger.String("provider", provider),
		logger.TenantID(tenantSlug),
		logger.Bool("created", isNew),
	)

	return userID, nil
}

func resolveDisplayName(claims *OIDCClaims) string {
	if claims == nil {
		return ""
	}
	if name := strings.TrimSpace(claims.Name); name != "" {
		return name
	}
	fullName := strings.TrimSpace(strings.TrimSpace(claims.GivenName + " " + claims.FamilyName))
	if fullName != "" {
		return fullName
	}
	return strings.TrimSpace(claims.Email)
}
