// Package admin provee controllers para operaciones administrativas HTTP V2.
package admin

import (
	"encoding/json"
	"errors"
	"net/http"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// AuthController maneja las peticiones HTTP de autenticación de admins.
type AuthController struct {
	service svc.AuthService
}

// NewAuthController crea un nuevo controller de autenticación de admins.
func NewAuthController(service svc.AuthService) *AuthController {
	return &AuthController{service: service}
}

// Login maneja el endpoint POST /v2/admin/login
func (c *AuthController) Login(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(
		logger.Layer("controller"),
		logger.Component("admin.auth"),
		logger.Op("Login"),
	)

	// 1. Validar método
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// 2. Parse request
	var req dto.AdminLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("invalid JSON", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	// 3. Validar campos requeridos
	if req.Email == "" || req.Password == "" {
		log.Warn("missing required fields")
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("email and password are required"))
		return
	}

	// 4. Delegar al service
	result, err := c.service.Login(ctx, req)
	if err != nil {
		c.writeLoginError(w, err)
		return
	}

	// 5. Response
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)

	log.Info("admin logged in successfully", logger.String("email", req.Email))
}

// Refresh maneja el endpoint POST /v2/admin/refresh
func (c *AuthController) Refresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(
		logger.Layer("controller"),
		logger.Component("admin.auth"),
		logger.Op("Refresh"),
	)

	// 1. Validar método
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// 2. Parse request
	var req dto.AdminRefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("invalid JSON", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	// 3. Validar campo requerido
	if req.RefreshToken == "" {
		log.Warn("missing refresh_token")
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("refresh_token is required"))
		return
	}

	// 4. Delegar al service
	result, err := c.service.Refresh(ctx, req)
	if err != nil {
		c.writeRefreshError(w, err)
		return
	}

	// 5. Response
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)

	log.Info("admin token refreshed successfully")
}

// writeLoginError mapea errores del service a HTTP responses.
func (c *AuthController) writeLoginError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, svc.ErrInvalidAdminCredentials):
		httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail("invalid admin credentials"))
	case errors.Is(err, svc.ErrAdminDisabled):
		httperrors.WriteError(w, httperrors.ErrForbidden.WithDetail("admin account disabled"))
	case errors.Is(err, svc.ErrAdminNotVerified):
		httperrors.WriteError(w, httperrors.ErrForbidden.WithDetail("admin email not verified"))
	default:
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
	}
}

// writeRefreshError mapea errores del service a HTTP responses.
func (c *AuthController) writeRefreshError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, svc.ErrInvalidRefreshToken):
		httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail("invalid refresh token"))
	case errors.Is(err, svc.ErrRefreshTokenExpired):
		httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail("refresh token expired"))
	case errors.Is(err, svc.ErrAdminDisabled):
		httperrors.WriteError(w, httperrors.ErrForbidden.WithDetail("admin account disabled"))
	default:
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
	}
}
