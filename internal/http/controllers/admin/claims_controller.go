package admin

import (
	"encoding/json"
	"net/http"
	"strings"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// ClaimsController maneja las rutas /v2/admin/claims
type ClaimsController struct {
	service svc.ClaimsService
}

// NewClaimsController crea un nuevo controller de claims.
func NewClaimsController(service svc.ClaimsService) *ClaimsController {
	return &ClaimsController{service: service}
}

// GetConfig maneja GET /v2/admin/claims
// Retorna configuraciÃ³n completa de claims (standard, custom, settings, mappings)
func (c *ClaimsController) GetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ClaimsController.GetConfig"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	config, err := c.service.GetConfig(ctx, tda.Slug())
	if err != nil {
		log.Error("get config failed", logger.Err(err))
		httperrors.WriteError(w, mapClaimError(err))
		return
	}

	writeJSON(w, http.StatusOK, config)
}

// ListCustomClaims maneja GET /v2/admin/claims/custom
func (c *ClaimsController) ListCustomClaims(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ClaimsController.ListCustomClaims"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	claims, err := c.service.ListCustomClaims(ctx, tda.Slug())
	if err != nil {
		log.Error("list custom claims failed", logger.Err(err))
		httperrors.WriteError(w, mapClaimError(err))
		return
	}

	writeJSON(w, http.StatusOK, claims)
}

// CreateCustomClaim maneja POST /v2/admin/claims/custom
func (c *ClaimsController) CreateCustomClaim(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ClaimsController.CreateCustomClaim"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	var req dto.ClaimCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		httperrors.WriteError(w, httperrors.ErrMissingFields.WithDetail("name is required"))
		return
	}

	claim, err := c.service.CreateCustomClaim(ctx, tda.Slug(), req)
	if err != nil {
		log.Error("create custom claim failed", logger.Err(err))
		httperrors.WriteError(w, mapClaimError(err))
		return
	}

	log.Info("custom claim created", logger.String("claim_name", claim.Name))
	writeJSON(w, http.StatusCreated, claim)
}

// GetCustomClaim maneja GET /v2/admin/claims/custom/{id}
func (c *ClaimsController) GetCustomClaim(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ClaimsController.GetCustomClaim"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	claimID := extractClaimID(r.URL.Path)
	if claimID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("missing claim id"))
		return
	}

	claim, err := c.service.GetCustomClaim(ctx, tda.Slug(), claimID)
	if err != nil {
		log.Error("get custom claim failed", logger.Err(err))
		httperrors.WriteError(w, mapClaimError(err))
		return
	}

	writeJSON(w, http.StatusOK, claim)
}

// UpdateCustomClaim maneja PUT /v2/admin/claims/custom/{id}
func (c *ClaimsController) UpdateCustomClaim(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ClaimsController.UpdateCustomClaim"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	claimID := extractClaimID(r.URL.Path)
	if claimID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("missing claim id"))
		return
	}

	var req dto.ClaimUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	claim, err := c.service.UpdateCustomClaim(ctx, tda.Slug(), claimID, req)
	if err != nil {
		log.Error("update custom claim failed", logger.Err(err))
		httperrors.WriteError(w, mapClaimError(err))
		return
	}

	log.Info("custom claim updated", logger.String("claim_id", claimID))
	writeJSON(w, http.StatusOK, claim)
}

// DeleteCustomClaim maneja DELETE /v2/admin/claims/custom/{id}
func (c *ClaimsController) DeleteCustomClaim(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ClaimsController.DeleteCustomClaim"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	claimID := extractClaimID(r.URL.Path)
	if claimID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("missing claim id"))
		return
	}

	if err := c.service.DeleteCustomClaim(ctx, tda.Slug(), claimID); err != nil {
		log.Error("delete custom claim failed", logger.Err(err))
		httperrors.WriteError(w, mapClaimError(err))
		return
	}

	log.Info("custom claim deleted", logger.String("claim_id", claimID))
	writeJSON(w, http.StatusOK, dto.StatusResponse{Status: "ok"})
}

// ToggleStandardClaim maneja PATCH /v2/admin/claims/standard/{name}
func (c *ClaimsController) ToggleStandardClaim(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ClaimsController.ToggleStandardClaim"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	claimName := extractStandardClaimName(r.URL.Path)
	if claimName == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("missing claim name"))
		return
	}

	var req dto.StandardClaimToggleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	if err := c.service.ToggleStandardClaim(ctx, tda.Slug(), claimName, req.Enabled); err != nil {
		log.Error("toggle standard claim failed", logger.Err(err))
		httperrors.WriteError(w, mapClaimError(err))
		return
	}

	log.Info("standard claim toggled", logger.String("claim_name", claimName), logger.Bool("enabled", req.Enabled))
	writeJSON(w, http.StatusOK, dto.StatusResponse{Status: "ok"})
}

// GetSettings maneja GET /v2/admin/claims/settings
func (c *ClaimsController) GetSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ClaimsController.GetSettings"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	settings, err := c.service.GetSettings(ctx, tda.Slug())
	if err != nil {
		log.Error("get settings failed", logger.Err(err))
		httperrors.WriteError(w, mapClaimError(err))
		return
	}

	writeJSON(w, http.StatusOK, settings)
}

// UpdateSettings maneja PATCH /v2/admin/claims/settings
func (c *ClaimsController) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ClaimsController.UpdateSettings"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	var req dto.ClaimsSettingsUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	settings, err := c.service.UpdateSettings(ctx, tda.Slug(), req)
	if err != nil {
		log.Error("update settings failed", logger.Err(err))
		httperrors.WriteError(w, mapClaimError(err))
		return
	}

	log.Info("claims settings updated")
	writeJSON(w, http.StatusOK, settings)
}

// GetScopeMappings maneja GET /v2/admin/claims/mappings
func (c *ClaimsController) GetScopeMappings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ClaimsController.GetScopeMappings"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	mappings, err := c.service.GetScopeMappings(ctx, tda.Slug())
	if err != nil {
		log.Error("get scope mappings failed", logger.Err(err))
		httperrors.WriteError(w, mapClaimError(err))
		return
	}

	writeJSON(w, http.StatusOK, mappings)
}

// â”€â”€â”€ Helpers â”€â”€â”€

// EvaluatePlayground maneja POST /v2/admin/claims/playground
func (c *ClaimsController) EvaluatePlayground(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ClaimsController.EvaluatePlayground"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(tenantRequired))
		return
	}

	var req dto.ClaimPlaygroundRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	result, err := c.service.EvaluatePlayground(ctx, tda.Slug(), req)
	if err != nil {
		log.Error("playground evaluation failed", logger.Err(err))
		httperrors.WriteError(w, mapClaimError(err))
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func extractClaimID(path string) string {
	const prefix = "/v2/admin/claims/custom/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	return strings.TrimPrefix(path, prefix)
}

func extractStandardClaimName(path string) string {
	const prefix = "/v2/admin/claims/standard/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	return strings.TrimPrefix(path, prefix)
}

func mapClaimError(err error) *httperrors.AppError {
	errMsg := err.Error()
	switch {
	case strings.Contains(errMsg, "not found"):
		return httperrors.ErrNotFound.WithDetail(errMsg)
	case strings.Contains(errMsg, "already exists"):
		return httperrors.ErrConflict.WithDetail(errMsg)
	case strings.Contains(errMsg, "required"):
		return httperrors.ErrBadRequest.WithDetail(errMsg)
	case strings.Contains(errMsg, "invalid"):
		return httperrors.ErrBadRequest.WithDetail(errMsg)
	default:
		return httperrors.ErrInternalServerError.WithCause(err)
	}
}
