package auth

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	"github.com/dropDatabas3/hellojohn/internal/http/helpers"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/auth"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"go.uber.org/zap"
)

const maxRegisterBodySize = 64 * 1024 // 64KB

// RegisterController handles POST /v2/auth/register.
type RegisterController struct {
	service svc.RegisterService
}

// NewRegisterController creates a new register controller.
func NewRegisterController(service svc.RegisterService) *RegisterController {
	return &RegisterController{service: service}
}

// Register handles user registration.
func (c *RegisterController) Register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("RegisterController.Register"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Limit body size
	r.Body = http.MaxBytesReader(w, r.Body, maxRegisterBodySize)
	defer r.Body.Close()

	var req dto.RegisterRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}
	// Check for extraneous data
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	// Extract client IP for bot protection validation
	req.RemoteIP = helpers.GetClientIP(r)

	result, err := c.service.Register(ctx, req)
	if err != nil {
		c.handleError(w, err, log)
		return
	}

	// Build response
	resp := dto.RegisterResponse{
		UserID:       result.UserID,
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresIn:    result.ExpiresIn,
	}
	if result.AccessToken != "" {
		resp.TokenType = "Bearer"
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)

	log.Info("user registered", logger.UserID(result.UserID))
}

// handleError maps service errors to HTTP responses.
func (c *RegisterController) handleError(w http.ResponseWriter, err error, log *zap.Logger) {
	switch {
	case errors.Is(err, svc.ErrRegisterMissingFields):
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("email, password, tenant_id and client_id are required"))
	case errors.Is(err, svc.ErrRegisterInvalidClient):
		httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail("invalid tenant or client"))
	case errors.Is(err, svc.ErrRegisterPasswordNotAllowed):
		httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail("password registration disabled for this client"))
	case errors.Is(err, svc.ErrRegisterEmailTaken):
		httperrors.WriteError(w, httperrors.ErrConflict.WithDetail("email already registered"))
	case errors.Is(err, svc.ErrRegisterPolicyViolation):
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("password does not meet policy requirements"))
	case errors.Is(err, svc.ErrNoDatabase):
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("database not available for this tenant"))
	case errors.Is(err, svc.ErrRegisterFSAdminNotAvailable):
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("FS-admin registration not available in V2 yet"))
	case errors.Is(err, svc.ErrRegisterHashFailed), errors.Is(err, svc.ErrRegisterCreateFailed), errors.Is(err, svc.ErrRegisterTokenFailed):
		log.Error("registration error", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
	default:
		log.Error("unexpected registration error", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
	}
}
