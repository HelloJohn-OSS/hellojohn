package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"github.com/google/uuid"
)

// UsersController maneja las rutas /v2/admin/users
type UsersController struct {
	service svc.UserActionService
}

// NewUsersController crea un nuevo controller de acciones de usuarios.
func NewUsersController(service svc.UserActionService) *UsersController {
	return &UsersController{service: service}
}

// Disable maneja POST /v2/admin/users/disable
func (c *UsersController) Disable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("UsersController.Disable"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	var req dto.UserActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	if req.UserID == "" {
		httperrors.WriteError(w, httperrors.ErrMissingFields.WithDetail("user_id is required"))
		return
	}
	if _, err := uuid.Parse(req.UserID); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidFormat.WithDetail("user_id must be a UUID"))
		return
	}

	// Parsear duraciÃ³n si viene
	var duration time.Duration
	if req.Duration != "" {
		d, err := time.ParseDuration(req.Duration)
		if err != nil {
			httperrors.WriteError(w, httperrors.ErrInvalidFormat.WithDetail("invalid duration (e.g. 1h, 30m)"))
			return
		}
		duration = d
	}

	// Obtener actor desde claims
	actor := getActor(ctx)

	if err := c.service.Disable(ctx, tda, req.UserID, req.Reason, duration, actor); err != nil {
		log.Error("disable failed", logger.Err(err))
		httperrors.WriteError(w, mapUserActionError(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Enable maneja POST /v2/admin/users/enable
func (c *UsersController) Enable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("UsersController.Enable"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	var req dto.UserActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	if req.UserID == "" {
		httperrors.WriteError(w, httperrors.ErrMissingFields.WithDetail("user_id is required"))
		return
	}
	if _, err := uuid.Parse(req.UserID); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidFormat.WithDetail("user_id must be a UUID"))
		return
	}

	actor := getActor(ctx)

	if err := c.service.Enable(ctx, tda, req.UserID, actor); err != nil {
		log.Error("enable failed", logger.Err(err))
		httperrors.WriteError(w, mapUserActionError(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ResendVerification maneja POST /v2/admin/users/resend-verification
func (c *UsersController) ResendVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("UsersController.ResendVerification"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	var req dto.UserActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	if req.UserID == "" {
		httperrors.WriteError(w, httperrors.ErrMissingFields.WithDetail("user_id is required"))
		return
	}
	if _, err := uuid.Parse(req.UserID); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidFormat.WithDetail("user_id must be a UUID"))
		return
	}

	actor := getActor(ctx)

	if err := c.service.ResendVerification(ctx, tda, req.UserID, actor); err != nil {
		log.Error("resend verification failed", logger.Err(err))
		httperrors.WriteError(w, mapUserActionError(err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// â”€â”€â”€ Helpers â”€â”€â”€

func getActor(ctx context.Context) string {
	if adminClaims := mw.GetAdminClaims(ctx); adminClaims != nil && adminClaims.AdminID != "" {
		return adminClaims.AdminID
	}
	claims := mw.GetClaims(ctx)
	if claims == nil {
		return ""
	}
	if sub, ok := claims["sub"].(string); ok {
		return sub
	}
	return ""
}

func mapUserActionError(err error) *httperrors.AppError {
	errMsg := err.Error()
	switch {
	case strings.Contains(errMsg, "not found"):
		return httperrors.ErrUserNotFound
	case strings.Contains(errMsg, "password policy violation"):
		return httperrors.ErrBadRequest.WithDetail(errMsg)
	case strings.Contains(errMsg, "already verified"):
		return httperrors.ErrBadRequest.WithDetail("email is already verified")
	case strings.Contains(errMsg, "no database") || strings.Contains(errMsg, "not available"):
		return httperrors.ErrServiceUnavailable.WithDetail(errMsg)
	case strings.Contains(errMsg, "email_error"):
		return httperrors.ErrInternalServerError.WithDetail("failed to send email")
	default:
		return httperrors.ErrInternalServerError.WithCause(err)
	}
}
