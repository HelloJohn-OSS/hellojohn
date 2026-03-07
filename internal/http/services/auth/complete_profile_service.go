package auth

import (
	"context"
	"fmt"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// CompleteProfileService defines operations for completing user profile.
type CompleteProfileService interface {
	CompleteProfile(ctx context.Context, tenantID, userID string, fields map[string]any) (*dto.CompleteProfileResult, error)
}

// CompleteProfileDeps contains dependencies for the complete profile service.
type CompleteProfileDeps struct {
	DAL store.DataAccessLayer
}

type completeProfileService struct {
	deps CompleteProfileDeps
}

// NewCompleteProfileService creates a new CompleteProfileService.
func NewCompleteProfileService(deps CompleteProfileDeps) CompleteProfileService {
	return &completeProfileService{deps: deps}
}

// CompleteProfile errors
var (
	ErrCompleteProfileEmptyFields   = fmt.Errorf("custom_fields is empty")
	ErrCompleteProfileUserNotFound  = fmt.Errorf("user not found")
	ErrCompleteProfileTenantInvalid = fmt.Errorf("invalid tenant")
	ErrCompleteProfileUpdateFailed  = fmt.Errorf("failed to update profile")
)

// CompleteProfile updates the custom_fields for an authenticated user.
func (s *completeProfileService) CompleteProfile(ctx context.Context, tenantID, userID string, fields map[string]any) (*dto.CompleteProfileResult, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("auth.complete_profile"),
		logger.Op("CompleteProfile"),
		logger.UserID(userID),
	)

	if len(fields) == 0 {
		return nil, ErrCompleteProfileEmptyFields
	}

	// Resolve tenant
	tda, err := s.deps.DAL.ForTenant(ctx, tenantID)
	if err != nil {
		log.Debug("tenant resolution failed", logger.Err(err))
		return nil, ErrCompleteProfileTenantInvalid
	}

	// Require DB for user operations
	if err := tda.RequireDB(); err != nil {
		log.Debug("tenant has no DB", logger.Err(err))
		return nil, ErrNoDatabase
	}

	log = log.With(logger.TenantSlug(tda.Slug()))

	// Get current user
	user, err := tda.Users().GetByID(ctx, userID)
	if err != nil {
		if err == repository.ErrNotFound {
			log.Debug("user not found")
			return nil, ErrCompleteProfileUserNotFound
		}
		log.Error("failed to get user", logger.Err(err))
		return nil, ErrCompleteProfileUpdateFailed
	}

	// Merge custom_fields with existing metadata
	customFields := s.mergeCustomFields(user.CustomFields, fields)

	// Update user with new custom_fields
	updateInput := repository.UpdateUserInput{
		CustomFields: customFields,
	}

	if err := tda.Users().Update(ctx, userID, updateInput); err != nil {
		log.Error("failed to update user custom_fields", logger.Err(err))
		return nil, ErrCompleteProfileUpdateFailed
	}

	log.Info("profile completed successfully")

	return &dto.CompleteProfileResult{
		Success: true,
		Message: "Profile updated successfully",
	}, nil
}

// mergeCustomFields merges new fields into existing custom fields.
func (s *completeProfileService) mergeCustomFields(existing, new map[string]any) map[string]any {
	if existing == nil {
		existing = make(map[string]any)
	}
	for k, v := range new {
		existing[k] = v
	}
	return existing
}
