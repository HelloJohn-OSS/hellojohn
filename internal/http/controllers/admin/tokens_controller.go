package admin

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// TokensController maneja las rutas /v2/admin/tenants/{id}/tokens
type TokensController struct {
	service svc.TokensAdminService
}

// NewTokensController crea un nuevo controller de tokens admin.
func NewTokensController(service svc.TokensAdminService) *TokensController {
	return &TokensController{service: service}
}

// List maneja GET /v2/admin/tenants/{id}/tokens
func (c *TokensController) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("TokensController.List"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	// Parse query params
	filter := dto.ListTokensFilter{
		Page:     1,
		PageSize: 50,
	}

	if page := r.URL.Query().Get("page"); page != "" {
		if p, err := strconv.Atoi(page); err == nil && p > 0 {
			filter.Page = p
		}
	}
	if pageSize := r.URL.Query().Get("page_size"); pageSize != "" {
		if ps, err := strconv.Atoi(pageSize); err == nil && ps > 0 && ps <= 200 {
			filter.PageSize = ps
		}
	}
	if userID := r.URL.Query().Get("user_id"); userID != "" {
		filter.UserID = &userID
	}
	if clientID := r.URL.Query().Get("client_id"); clientID != "" {
		filter.ClientID = &clientID
	}
	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = &status
	}
	if search := r.URL.Query().Get("search"); search != "" {
		filter.Search = &search
	}

	resp, err := c.service.List(ctx, tda.Slug(), filter)
	if err != nil {
		log.Error("list failed", logger.Err(err))
		httperrors.WriteError(w, mapTokenError(err))
		return
	}

	log.Debug("tokens listed", logger.Int("count", len(resp.Tokens)))
	writeJSON(w, http.StatusOK, resp)
}

// Get maneja GET /v2/admin/tenants/{id}/tokens/{tokenId}
func (c *TokensController) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("TokensController.Get"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	tokenID := extractTokenID(r.URL.Path)
	if tokenID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("token_id is required"))
		return
	}

	resp, err := c.service.Get(ctx, tda.Slug(), tokenID)
	if err != nil {
		log.Error("get failed", logger.Err(err))
		httperrors.WriteError(w, mapTokenError(err))
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// Revoke maneja DELETE /v2/admin/tenants/{id}/tokens/{tokenId}
func (c *TokensController) Revoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("TokensController.Revoke"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	tokenID := extractTokenID(r.URL.Path)
	if tokenID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("token_id is required"))
		return
	}

	if err := c.service.Revoke(ctx, tda.Slug(), tokenID); err != nil {
		log.Error("revoke failed", logger.Err(err))
		httperrors.WriteError(w, mapTokenError(err))
		return
	}

	log.Info("token revoked", logger.String("token_id", tokenID))
	writeJSON(w, http.StatusOK, dto.StatusResponse{Status: "ok"})
}

// RevokeByUser maneja POST /v2/admin/tenants/{id}/tokens/revoke-by-user
func (c *TokensController) RevokeByUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("TokensController.RevokeByUser"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	var req dto.RevokeByUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	if req.UserID == "" {
		httperrors.WriteError(w, httperrors.ErrMissingFields.WithDetail("user_id is required"))
		return
	}

	resp, err := c.service.RevokeByUser(ctx, tda.Slug(), req.UserID)
	if err != nil {
		log.Error("revoke by user failed", logger.Err(err))
		httperrors.WriteError(w, mapTokenError(err))
		return
	}

	log.Info("tokens revoked by user", logger.UserID(req.UserID), logger.Int("count", resp.RevokedCount))
	writeJSON(w, http.StatusOK, resp)
}

// RevokeByClient maneja POST /v2/admin/tenants/{id}/tokens/revoke-by-client
func (c *TokensController) RevokeByClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("TokensController.RevokeByClient"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	var req dto.RevokeByClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	if req.ClientID == "" {
		httperrors.WriteError(w, httperrors.ErrMissingFields.WithDetail("client_id is required"))
		return
	}

	resp, err := c.service.RevokeByClient(ctx, tda.Slug(), req.ClientID)
	if err != nil {
		log.Error("revoke by client failed", logger.Err(err))
		httperrors.WriteError(w, mapTokenError(err))
		return
	}

	log.Info("tokens revoked by client", logger.String("client_id", req.ClientID), logger.Int("count", resp.RevokedCount))
	writeJSON(w, http.StatusOK, resp)
}

// RevokeAll maneja POST /v2/admin/tenants/{id}/tokens/revoke-all
func (c *TokensController) RevokeAll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("TokensController.RevokeAll"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	resp, err := c.service.RevokeAll(ctx, tda.Slug())
	if err != nil {
		log.Error("revoke all failed", logger.Err(err))
		httperrors.WriteError(w, mapTokenError(err))
		return
	}

	log.Warn("all tokens revoked", logger.Int("count", resp.RevokedCount))
	writeJSON(w, http.StatusOK, resp)
}

// GetStats maneja GET /v2/admin/tenants/{id}/tokens/stats
func (c *TokensController) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("TokensController.GetStats"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	resp, err := c.service.GetStats(ctx, tda.Slug())
	if err != nil {
		log.Error("get stats failed", logger.Err(err))
		httperrors.WriteError(w, mapTokenError(err))
		return
	}

	log.Debug("stats retrieved", logger.Int("total_active", resp.TotalActive))
	writeJSON(w, http.StatusOK, resp)
}

// ─── Helpers ───

// extractTokenID extrae el token ID del path /v2/admin/tenants/{id}/tokens/{tokenId}
func extractTokenID(path string) string {
	// Path: /v2/admin/tenants/{id}/tokens/{tokenId}
	parts := strings.Split(path, "/tokens/")
	if len(parts) < 2 {
		return ""
	}
	// Remove trailing slash and any suffix
	tokenID := strings.TrimSuffix(parts[1], "/")
	// Handle case where there might be additional path segments
	if idx := strings.Index(tokenID, "/"); idx != -1 {
		tokenID = tokenID[:idx]
	}
	return tokenID
}

func mapTokenError(err error) *httperrors.AppError {
	errMsg := err.Error()
	switch {
	case strings.Contains(errMsg, "not found"):
		return httperrors.ErrNotFound.WithDetail(errMsg)
	case strings.Contains(errMsg, "no database"):
		return httperrors.ErrServiceUnavailable.WithDetail("Tenant has no database configured")
	case strings.Contains(errMsg, "required"):
		return httperrors.ErrBadRequest.WithDetail(errMsg)
	default:
		return httperrors.ErrInternalServerError.WithCause(err)
	}
}
