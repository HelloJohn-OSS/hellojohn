package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// UsersCRUDController maneja las operaciones CRUD de usuarios.
type UsersCRUDController struct {
	service       svc.UserCRUDService
	actionService svc.UserActionService
	dal           store.DataAccessLayer
}

// NewUsersCRUDController crea una nueva instancia del controller.
func NewUsersCRUDController(service svc.UserCRUDService) *UsersCRUDController {
	return &UsersCRUDController{service: service}
}

// NewUsersCRUDControllerWithActions crea un controller con soporte para acciones de usuario.
func NewUsersCRUDControllerWithActions(service svc.UserCRUDService, actionService svc.UserActionService, dal store.DataAccessLayer) *UsersCRUDController {
	return &UsersCRUDController{
		service:       service,
		actionService: actionService,
		dal:           dal,
	}
}

// CreateUser maneja POST /v2/admin/tenants/{id}/users
func (c *UsersCRUDController) CreateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx)

	// 1. Validar método
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// 2. Extraer tenant ID del path
	// Path: /v2/admin/tenants/{id}/users
	tenantID := extractTenantIDFromPath(r.URL.Path)
	if tenantID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant_id is required in path"))
		return
	}

	// 3. Parse request body
	var req dto.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("invalid JSON", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	// 4. Llamar al service
	result, err := c.service.Create(ctx, tenantID, req)
	if err != nil {
		c.writeUserCRUDError(w, err)
		return
	}

	// 5. Response
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(result)
}

// ListUsers maneja GET /v2/admin/tenants/{id}/users
func (c *UsersCRUDController) ListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx)

	// 1. Validar método
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// 2. Extraer tenant ID del path
	tenantID := extractTenantIDFromPath(r.URL.Path)
	if tenantID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant_id is required in path"))
		return
	}

	// 3. Parse query params
	page := parseIntQuery(r, "page", 1)
	pageSize := parseIntQuery(r, "page_size", 50)
	search := r.URL.Query().Get("search")

	// 4. Llamar al service
	result, err := c.service.List(ctx, tenantID, page, pageSize, search)
	if err != nil {
		c.writeUserCRUDError(w, err)
		return
	}

	// 5. Response
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)

	log.Info("users listed", logger.Int("count", len(result.Users)), logger.Int("page", page))
}

// GetUser maneja GET /v2/admin/tenants/{id}/users/{userId}
func (c *UsersCRUDController) GetUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 1. Validar método
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// 2. Extraer tenant ID y user ID del path
	tenantID, userID := extractTenantAndUserIDFromPath(r.URL.Path)
	if tenantID == "" || userID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant_id and user_id are required in path"))
		return
	}

	// 3. Llamar al service
	result, err := c.service.Get(ctx, tenantID, userID)
	if err != nil {
		c.writeUserCRUDError(w, err)
		return
	}

	// 4. Response
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(result)
}

// UpdateUser maneja PUT /v2/admin/tenants/{id}/users/{userId}
func (c *UsersCRUDController) UpdateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx)

	// 1. Validar método
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", "PUT")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// 2. Extraer tenant ID y user ID del path
	tenantID, userID := extractTenantAndUserIDFromPath(r.URL.Path)
	if tenantID == "" || userID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant_id and user_id are required in path"))
		return
	}

	// 3. Parse request body
	var req dto.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("invalid JSON", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	// 4. Llamar al service
	err := c.service.Update(ctx, tenantID, userID, req)
	if err != nil {
		c.writeUserCRUDError(w, err)
		return
	}

	// 5. Response (204 No Content)
	w.WriteHeader(http.StatusNoContent)
}

// DeleteUser maneja DELETE /v2/admin/tenants/{id}/users/{userId}
func (c *UsersCRUDController) DeleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx)

	// 1. Validar método
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", "DELETE")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// 2. Extraer tenant ID y user ID del path
	tenantID, userID := extractTenantAndUserIDFromPath(r.URL.Path)
	if tenantID == "" || userID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant_id and user_id are required in path"))
		return
	}

	// 3. Llamar al service
	err := c.service.Delete(ctx, tenantID, userID)
	if err != nil {
		c.writeUserCRUDError(w, err)
		return
	}

	// 4. Response (204 No Content)
	w.WriteHeader(http.StatusNoContent)

	log.Info("user deleted", logger.UserID(userID))
}

// writeUserCRUDError mapea errores del service a HTTP.
func (c *UsersCRUDController) writeUserCRUDError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, svc.ErrUserInvalidInput):
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(err.Error()))
	case errors.Is(err, svc.ErrUserNotFound):
		httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("user not found"))
	case errors.Is(err, svc.ErrUserEmailDuplicate):
		httperrors.WriteError(w, httperrors.ErrConflict.WithDetail("email already exists"))
	case errors.Is(err, svc.ErrUserTenantNotFound):
		httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("tenant not found"))
	case errors.Is(err, svc.ErrUserTenantNoDB):
		httperrors.WriteError(w, httperrors.ErrTenantNoDatabase.WithDetail("tenant has no database configured"))
	default:
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
	}
}

// ─── Path Helpers ───

// extractTenantIDFromPath extrae el tenant ID de /v2/admin/tenants/{id}/users
func extractTenantIDFromPath(path string) string {
	// Path: /v2/admin/tenants/{id}/users
	// Remover prefix y suffix
	path = strings.TrimPrefix(path, "/v2/admin/tenants/")
	if idx := strings.Index(path, "/"); idx > 0 {
		return path[:idx]
	}
	return ""
}

// extractTenantAndUserIDFromPath extrae tenant ID y user ID de /v2/admin/tenants/{id}/users/{userId}
func extractTenantAndUserIDFromPath(path string) (string, string) {
	// Path: /v2/admin/tenants/{id}/users/{userId}
	path = strings.TrimPrefix(path, "/v2/admin/tenants/")
	parts := strings.Split(path, "/")

	if len(parts) >= 3 && parts[1] == "users" {
		return parts[0], parts[2]
	}

	return "", ""
}

// parseIntQuery parsea un query param como int con valor por defecto.
func parseIntQuery(r *http.Request, key string, defaultValue int) int {
	val := r.URL.Query().Get(key)
	if val == "" {
		return defaultValue
	}

	parsed, err := strconv.Atoi(val)
	if err != nil {
		return defaultValue
	}

	return parsed
}

// ─── User Actions (tenant-scoped) ───

// DisableUser maneja POST /v2/admin/tenants/{id}/users/{userId}/disable
func (c *UsersCRUDController) DisableUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx)

	if c.actionService == nil || c.dal == nil {
		httperrors.WriteError(w, httperrors.ErrInternalServerError.WithDetail("action service not configured"))
		return
	}

	// Extraer tenant ID y user ID del path
	tenantID, userID := extractTenantUserAndActionFromPath(r.URL.Path)
	if tenantID == "" || userID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant_id and user_id are required in path"))
		return
	}

	// Parse body
	var req dto.UserActionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	// Parse duration
	var duration time.Duration
	if req.Duration != "" {
		var err error
		duration, err = time.ParseDuration(req.Duration)
		if err != nil {
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invalid duration format"))
			return
		}
	}

	// Obtener TDA
	tda, err := c.dal.ForTenant(ctx, tenantID)
	if err != nil {
		log.Warn("tenant not found", logger.TenantID(tenantID), logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("tenant not found"))
		return
	}

	// Llamar service
	if err := c.actionService.Disable(ctx, tda, userID, req.Reason, duration, adminActorID(ctx)); err != nil {
		log.Error("disable failed", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(dto.UserActionResponse{Status: "disabled"})
}

// EnableUser maneja POST /v2/admin/tenants/{id}/users/{userId}/enable
func (c *UsersCRUDController) EnableUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx)

	if c.actionService == nil || c.dal == nil {
		httperrors.WriteError(w, httperrors.ErrInternalServerError.WithDetail("action service not configured"))
		return
	}

	tenantID, userID := extractTenantUserAndActionFromPath(r.URL.Path)
	if tenantID == "" || userID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant_id and user_id are required in path"))
		return
	}

	tda, err := c.dal.ForTenant(ctx, tenantID)
	if err != nil {
		log.Warn("tenant not found", logger.TenantID(tenantID), logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("tenant not found"))
		return
	}

	if err := c.actionService.Enable(ctx, tda, userID, adminActorID(ctx)); err != nil {
		log.Error("enable failed", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(dto.UserActionResponse{Status: "enabled"})
}

// SetEmailVerified maneja POST /v2/admin/tenants/{id}/users/{userId}/set-email-verified
func (c *UsersCRUDController) SetEmailVerified(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx)

	if c.actionService == nil || c.dal == nil {
		httperrors.WriteError(w, httperrors.ErrInternalServerError.WithDetail("action service not configured"))
		return
	}

	tenantID, userID := extractTenantUserAndActionFromPath(r.URL.Path)
	if tenantID == "" || userID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant_id and user_id are required in path"))
		return
	}

	var req dto.SetEmailVerifiedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	tda, err := c.dal.ForTenant(ctx, tenantID)
	if err != nil {
		log.Warn("tenant not found", logger.TenantID(tenantID), logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("tenant not found"))
		return
	}

	if err := c.actionService.SetEmailVerified(ctx, tda, userID, req.Verified, adminActorID(ctx)); err != nil {
		log.Error("set email verified failed", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(dto.UserActionResponse{Status: "email_verified_updated"})
}

// SetPassword maneja POST /v2/admin/tenants/{id}/users/{userId}/set-password
func (c *UsersCRUDController) SetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx)

	if c.actionService == nil || c.dal == nil {
		httperrors.WriteError(w, httperrors.ErrInternalServerError.WithDetail("action service not configured"))
		return
	}

	tenantID, userID := extractTenantUserAndActionFromPath(r.URL.Path)
	if tenantID == "" || userID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant_id and user_id are required in path"))
		return
	}

	var req dto.SetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	if req.Password == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("password is required"))
		return
	}

	tda, err := c.dal.ForTenant(ctx, tenantID)
	if err != nil {
		log.Warn("tenant not found", logger.TenantID(tenantID), logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("tenant not found"))
		return
	}

	if err := c.actionService.SetPassword(ctx, tda, userID, req.Password, adminActorID(ctx)); err != nil {
		log.Error("set password failed", logger.Err(err))
		httperrors.WriteError(w, mapUserActionError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(dto.UserActionResponse{Status: "password_updated"})
}

// extractTenantUserAndActionFromPath extrae tenant ID, user ID y acción del path.
// Path: /v2/admin/tenants/{id}/users/{userId}/{action}
func extractTenantUserAndActionFromPath(path string) (tenantID, userID string) {
	path = strings.TrimPrefix(path, "/v2/admin/tenants/")
	parts := strings.Split(path, "/")

	// parts[0] = tenantID, parts[1] = "users", parts[2] = userID, parts[3] = action
	if len(parts) >= 3 && parts[1] == "users" {
		return parts[0], parts[2]
	}

	return "", ""
}

func adminActorID(ctx context.Context) string {
	if claims := mw.GetAdminClaims(ctx); claims != nil && strings.TrimSpace(claims.AdminID) != "" {
		return claims.AdminID
	}
	return ""
}
