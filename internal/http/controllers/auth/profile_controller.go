package auth

import (
	"encoding/json"
	"net/http"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/auth"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"go.uber.org/zap"
)

// ProfileController handles GET /v2/profile.
type ProfileController struct {
	service svc.ProfileService
}

// NewProfileController creates a new profile controller.
func NewProfileController(service svc.ProfileService) *ProfileController {
	return &ProfileController{service: service}
}

// GetProfile handles the request to get user profile.
// Requires authentication via Bearer token and scope profile:read.
func (c *ProfileController) GetProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ProfileController.GetProfile"))

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Get claims from context (set by RequireAuth middleware)
	claims := mw.GetClaims(ctx)
	if claims == nil {
		httperrors.WriteError(w, httperrors.ErrUnauthorized)
		return
	}

	userID, _ := claims["sub"].(string)
	tenantID, _ := claims["tid"].(string)

	if userID == "" {
		httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail("sub missing in token"))
		return
	}

	log = log.With(logger.UserID(userID), zap.String("tenant_id", tenantID))

	result, err := c.service.GetProfile(ctx, userID, tenantID)
	if err != nil {
		c.handleError(w, err, log)
		return
	}

	// Build response
	resp := dto.ProfileResponse{
		Sub:           result.Sub,
		Email:         result.Email,
		EmailVerified: result.EmailVerified,
		Name:          result.Name,
		GivenName:     result.GivenName,
		FamilyName:    result.FamilyName,
		Picture:       result.Picture,
		UpdatedAt:     result.UpdatedAt,
	}

	// Security headers for PII
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)

	log.Debug("profile returned")
}

// handleError maps service errors to HTTP responses.
func (c *ProfileController) handleError(w http.ResponseWriter, err error, log *zap.Logger) {
	switch err {
	case svc.ErrProfileUserNotFound:
		httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("user not found"))
	case svc.ErrProfileTenantMismatch:
		httperrors.WriteError(w, httperrors.ErrForbidden.WithDetail("tenant mismatch"))
	case svc.ErrProfileTenantInvalid:
		httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail("invalid tenant"))
	case svc.ErrNoDatabase:
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("database not available"))
	default:
		log.Error("unexpected error", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
	}
}
