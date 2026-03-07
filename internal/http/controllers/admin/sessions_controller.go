// Package admin contiene controladores de administración.
package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	adminsvc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// SessionsController maneja endpoints de administración de sesiones.
type SessionsController struct {
	service *adminsvc.SessionsService
}

// NewSessionsController crea un nuevo controlador de sesiones.
func NewSessionsController(service *adminsvc.SessionsService) *SessionsController {
	return &SessionsController{service: service}
}

// ListSessions godoc
// @Summary Listar sesiones activas
// @Description Retorna una lista paginada de sesiones del tenant
// @Tags Admin Sessions
// @Accept json
// @Produce json
// @Param tenant path string true "Slug del tenant"
// @Param user_id query string false "Filtrar por usuario"
// @Param device_type query string false "Filtrar por tipo de dispositivo"
// @Param status query string false "Filtrar por estado (active, expired, revoked)"
// @Param search query string false "Buscar por IP o ubicación"
// @Param page query int false "Página" default(1)
// @Param page_size query int false "Tamaño de página" default(20)
// @Success 200 {object} adminsvc.ListSessionsOutput
// @Router /admin/tenants/{tenant}/sessions [get]
func (c *SessionsController) ListSessions(w http.ResponseWriter, r *http.Request) {
	tenantSlug := r.PathValue("tenant_id")
	if tenantSlug == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant slug required"))
		return
	}

	// Parse query params
	userID := r.URL.Query().Get("user_id")
	deviceType := r.URL.Query().Get("device_type")
	status := r.URL.Query().Get("status")
	search := r.URL.Query().Get("search")

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 {
		pageSize = 20
	}
	const maxPageSize = 200
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}

	input := adminsvc.ListSessionsInput{
		TenantSlug: tenantSlug,
		Page:       page,
		PageSize:   pageSize,
	}
	if userID != "" {
		input.UserID = &userID
	}
	if deviceType != "" {
		input.DeviceType = &deviceType
	}
	if status != "" {
		input.Status = &status
	}
	if search != "" {
		input.Search = &search
	}

	result, err := c.service.List(r.Context(), input)
	if err != nil {
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// RevokeSessionRequest representa el body para revocar una sesión.
type RevokeSessionRequest struct {
	Reason string `json:"reason"`
}

// RevokeSession godoc
// @Summary Revocar una sesión
// @Description Revoca una sesión específica por su ID hash
// @Tags Admin Sessions
// @Accept json
// @Produce json
// @Param tenant path string true "Slug del tenant"
// @Param session_id path string true "Hash del session ID"
// @Param body body RevokeSessionRequest true "Razón de revocación"
// @Success 200 {object} map[string]string
// @Router /admin/tenants/{tenant}/sessions/{session_id}/revoke [post]
func (c *SessionsController) RevokeSession(w http.ResponseWriter, r *http.Request) {
	tenantSlug := r.PathValue("tenant_id")
	sessionID := r.PathValue("sessionId")

	if tenantSlug == "" || sessionID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant slug and session_id required"))
		return
	}

	var req RevokeSessionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invalid request body"))
		return
	}

	var adminID string
	if claims := mw.GetAdminClaims(r.Context()); claims != nil {
		adminID = claims.AdminID
	}

	err := c.service.RevokeSession(r.Context(), adminsvc.RevokeSessionInput{
		TenantSlug:    tenantSlug,
		SessionIDHash: sessionID,
		AdminID:       adminID,
		Reason:        req.Reason,
	})
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("session not found"))
			return
		}
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "revoked"})
}

// RevokeUserSessionsRequest representa el body para revocar sesiones de un usuario.
type RevokeUserSessionsRequest struct {
	Reason string `json:"reason"`
}

// RevokeUserSessions godoc
// @Summary Revocar todas las sesiones de un usuario
// @Description Revoca todas las sesiones activas de un usuario específico
// @Tags Admin Sessions
// @Accept json
// @Produce json
// @Param tenant path string true "Slug del tenant"
// @Param user_id path string true "ID del usuario"
// @Param body body RevokeUserSessionsRequest true "Razón de revocación"
// @Success 200 {object} adminsvc.RevokeUserSessionsOutput
// @Router /admin/tenants/{tenant}/users/{user_id}/sessions/revoke [post]
func (c *SessionsController) RevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	tenantSlug := r.PathValue("tenant_id")

	if tenantSlug == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant slug required"))
		return
	}

	var body struct {
		UserID string `json:"user_id"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}
	if body.UserID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("user_id is required"))
		return
	}

	var adminID string
	if claims := mw.GetAdminClaims(r.Context()); claims != nil {
		adminID = claims.AdminID
	}

	result, err := c.service.RevokeUserSessions(r.Context(), adminsvc.RevokeUserSessionsInput{
		TenantSlug: tenantSlug,
		UserID:     body.UserID,
		AdminID:    adminID,
		Reason:     body.Reason,
	})
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("session not found"))
			return
		}
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// RevokeAllSessionsRequest representa el body para revocar todas las sesiones.
type RevokeAllSessionsRequest struct {
	Reason string `json:"reason"`
}

// RevokeAllSessions godoc
// @Summary Revocar todas las sesiones del tenant
// @Description Revoca todas las sesiones activas del tenant (nuclear option)
// @Tags Admin Sessions
// @Accept json
// @Produce json
// @Param tenant path string true "Slug del tenant"
// @Param body body RevokeAllSessionsRequest true "Razón de revocación"
// @Success 200 {object} adminsvc.RevokeUserSessionsOutput
// @Router /admin/tenants/{tenant}/sessions/revoke-all [post]
func (c *SessionsController) RevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	tenantSlug := r.PathValue("tenant_id")

	if tenantSlug == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant slug required"))
		return
	}

	var req RevokeAllSessionsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invalid request body"))
		return
	}

	var adminID string
	if claims := mw.GetAdminClaims(r.Context()); claims != nil {
		adminID = claims.AdminID
	}

	result, err := c.service.RevokeAllSessions(r.Context(), adminsvc.RevokeAllSessionsInput{
		TenantSlug: tenantSlug,
		AdminID:    adminID,
		Reason:     req.Reason,
	})
	if err != nil {
		if errors.Is(err, store.ErrNoDBForTenant) {
			httperrors.WriteError(w, httperrors.ErrUnprocessableEntity.WithDetail("tenant has no database configured"))
			return
		}
		if errors.Is(err, repository.ErrNotFound) {
			httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("session not found"))
			return
		}
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// GetSession godoc
// @Summary Obtener una sesión específica
// @Description Retorna los detalles de una sesión por su hash
// @Tags Admin Sessions
// @Accept json
// @Produce json
// @Param tenant path string true "Slug del tenant"
// @Param session_id path string true "Hash del session ID"
// @Success 200 {object} adminsvc.SessionItem
// @Router /admin/tenants/{tenant}/sessions/{session_id} [get]
func (c *SessionsController) GetSession(w http.ResponseWriter, r *http.Request) {
	tenantSlug := r.PathValue("tenant_id")
	sessionID := r.PathValue("sessionId")

	if tenantSlug == "" || sessionID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant slug and session_id required"))
		return
	}

	result, err := c.service.GetSession(r.Context(), adminsvc.GetSessionInput{
		TenantSlug:    tenantSlug,
		SessionIDHash: sessionID,
	})
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("session not found"))
			return
		}
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// GetStats godoc
// @Summary Obtener estadísticas de sesiones
// @Description Retorna estadísticas agregadas de sesiones del tenant
// @Tags Admin Sessions
// @Accept json
// @Produce json
// @Param tenant path string true "Slug del tenant"
// @Success 200 {object} adminsvc.SessionStatsOutput
// @Router /admin/tenants/{tenant}/sessions/stats [get]
func (c *SessionsController) GetStats(w http.ResponseWriter, r *http.Request) {
	tenantSlug := r.PathValue("tenant_id")

	if tenantSlug == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant slug required"))
		return
	}

	result, err := c.service.GetStats(r.Context(), adminsvc.GetStatsInput{
		TenantSlug: tenantSlug,
	})
	if err != nil {
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
