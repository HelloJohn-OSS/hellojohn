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

const maxCompleteProfileBodySize = 64 * 1024 // 64KB

// CompleteProfileController handles POST /v2/auth/complete-profile.
type CompleteProfileController struct {
	service svc.CompleteProfileService
}

// NewCompleteProfileController creates a new complete profile controller.
func NewCompleteProfileController(service svc.CompleteProfileService) *CompleteProfileController {
	return &CompleteProfileController{service: service}
}

// CompleteProfile handles the request to update user custom_fields.
// Requires authentication via Bearer token.
func (c *CompleteProfileController) CompleteProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("CompleteProfileController.CompleteProfile"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
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

	if userID == "" || tenantID == "" {
		httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail("sub/tid missing in token"))
		return
	}

	log = log.With(logger.UserID(userID), zap.String("tenant_id", tenantID))

	// Limit body size
	r.Body = http.MaxBytesReader(w, r.Body, maxCompleteProfileBodySize)
	defer r.Body.Close()

	var req dto.CompleteProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	result, err := c.service.CompleteProfile(ctx, tenantID, userID, req.CustomFields)
	if err != nil {
		c.handleError(w, err, log)
		return
	}

	// Build response
	resp := dto.CompleteProfileResponse{
		Success: result.Success,
		Message: result.Message,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)

	log.Info("profile completed")
}

// handleError maps service errors to HTTP responses.
func (c *CompleteProfileController) handleError(w http.ResponseWriter, err error, log *zap.Logger) {
	switch err {
	case svc.ErrCompleteProfileEmptyFields:
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("custom_fields is empty"))
	case svc.ErrCompleteProfileUserNotFound:
		httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("user not found"))
	case svc.ErrCompleteProfileTenantInvalid:
		httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail("invalid tenant"))
	case svc.ErrNoDatabase:
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("database not available"))
	case svc.ErrCompleteProfileUpdateFailed:
		log.Error("profile update failed", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
	default:
		log.Error("unexpected error", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
	}
}
