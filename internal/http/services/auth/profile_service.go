package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	"go.uber.org/zap"
)

// ProfileService defines operations for user profile.
type ProfileService interface {
	GetProfile(ctx context.Context, userID, tenantID string) (*dto.ProfileResult, error)
}

// ProfileDeps contains dependencies for the profile service.
type ProfileDeps struct {
	DAL store.DataAccessLayer
}

type profileService struct {
	deps ProfileDeps
}

// NewProfileService creates a new ProfileService.
func NewProfileService(deps ProfileDeps) ProfileService {
	return &profileService{deps: deps}
}

// Profile service errors
var (
	ErrProfileUserNotFound   = fmt.Errorf("user not found")
	ErrProfileTenantMismatch = fmt.Errorf("tenant mismatch")
	ErrProfileTenantInvalid  = fmt.Errorf("invalid tenant")
)

// GetProfile returns the profile for the authenticated user.
func (s *profileService) GetProfile(ctx context.Context, userID, tenantID string) (*dto.ProfileResult, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("auth.profile"),
		logger.Op("GetProfile"),
		logger.UserID(userID),
	)

	if userID == "" {
		return nil, ErrProfileUserNotFound
	}

	// Resolve tenant
	tda, err := s.deps.DAL.ForTenant(ctx, tenantID)
	if err != nil {
		log.Debug("tenant resolution failed", logger.Err(err))
		return nil, ErrProfileTenantInvalid
	}

	// RequireDB for user operations
	if err := tda.RequireDB(); err != nil {
		log.Debug("tenant has no DB", logger.Err(err))
		return nil, ErrNoDatabase
	}

	log = log.With(logger.TenantSlug(tda.Slug()))

	// Get user
	user, err := tda.Users().GetByID(ctx, userID)
	if err != nil {
		if err == repository.ErrNotFound {
			log.Debug("user not found")
			return nil, ErrProfileUserNotFound
		}
		log.Error("failed to get user", logger.Err(err))
		return nil, ErrProfileUserNotFound
	}

	// Multi-tenant guard: ensure user belongs to the tenant
	if tenantID != "" && !strings.EqualFold(strings.TrimSpace(tenantID), strings.TrimSpace(user.TenantID)) {
		log.Warn("tenant mismatch",
			zap.String("token_tid", tenantID),
			zap.String("user_tid", user.TenantID),
		)
		return nil, ErrProfileTenantMismatch
	}

	// Build profile from user data
	result := s.buildProfile(user)

	log.Debug("profile retrieved")
	return result, nil
}

// buildProfile extracts profile data from user.
func (s *profileService) buildProfile(user *repository.User) *dto.ProfileResult {
	givenName := ""
	familyName := ""
	name := ""
	picture := ""

	// Extract from Metadata or CustomFields
	if user.Metadata != nil {
		if v, ok := user.Metadata["given_name"].(string); ok {
			givenName = strings.TrimSpace(v)
		}
		if v, ok := user.Metadata["family_name"].(string); ok {
			familyName = strings.TrimSpace(v)
		}
		if v, ok := user.Metadata["name"].(string); ok {
			name = strings.TrimSpace(v)
		}
		if v, ok := user.Metadata["picture"].(string); ok {
			picture = strings.TrimSpace(v)
		}
	}

	// Also check CustomFields as fallback
	if user.CustomFields != nil {
		if givenName == "" {
			if v, ok := user.CustomFields["given_name"].(string); ok {
				givenName = strings.TrimSpace(v)
			}
		}
		if familyName == "" {
			if v, ok := user.CustomFields["family_name"].(string); ok {
				familyName = strings.TrimSpace(v)
			}
		}
		if name == "" {
			if v, ok := user.CustomFields["name"].(string); ok {
				name = strings.TrimSpace(v)
			}
		}
		if picture == "" {
			if v, ok := user.CustomFields["picture"].(string); ok {
				picture = strings.TrimSpace(v)
			}
		}
	}

	// Build name from parts if not set
	if name == "" && (givenName != "" || familyName != "") {
		name = strings.TrimSpace(givenName + " " + familyName)
	}

	// UpdatedAt: use CreatedAt as placeholder (best-effort)
	updatedAt := user.CreatedAt.Unix()

	return &dto.ProfileResult{
		Sub:           user.ID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Name:          name,
		GivenName:     givenName,
		FamilyName:    familyName,
		Picture:       picture,
		UpdatedAt:     updatedAt,
	}
}
