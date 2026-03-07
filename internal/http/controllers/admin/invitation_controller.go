package admin

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
)

const maxInvitationBodySize = 64 * 1024 // 64KB

// InvitationController maneja operaciones admin sobre invitaciones.
type InvitationController struct {
	service svc.InvitationService
}

// NewInvitationController crea un InvitationController.
func NewInvitationController(service svc.InvitationService) *InvitationController {
	return &InvitationController{service: service}
}

// Create maneja POST /v2/admin/tenants/{tenant_id}/invitations.
func (c *InvitationController) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	adminClaims := mw.GetAdminClaims(ctx)
	if adminClaims == nil || strings.TrimSpace(adminClaims.AdminID) == "" {
		httperrors.WriteError(w, httperrors.ErrUnauthorized)
		return
	}

	tenantID := strings.TrimSpace(r.PathValue("tenant_id"))
	if tenantID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant_id is required"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxInvitationBodySize)
	defer r.Body.Close()

	var req dto.CreateInvitationRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	resp, rawToken, err := c.service.Create(ctx, tenantID, adminClaims.AdminID, req)
	if err != nil {
		c.writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"invitation":      resp,
		"invitationToken": rawToken,
	})
}

// List maneja GET /v2/admin/tenants/{tenant_id}/invitations.
func (c *InvitationController) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := strings.TrimSpace(r.PathValue("tenant_id"))
	if tenantID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant_id is required"))
		return
	}

	var statusPtr *string
	if status := strings.TrimSpace(r.URL.Query().Get("status")); status != "" {
		statusPtr = &status
	}

	limit := 20
	offset := 0
	if qLimit := strings.TrimSpace(r.URL.Query().Get("limit")); qLimit != "" {
		n, err := strconv.Atoi(qLimit)
		if err != nil || n < 1 {
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("limit must be a positive integer"))
			return
		}
		limit = n
	}
	if qOffset := strings.TrimSpace(r.URL.Query().Get("offset")); qOffset != "" {
		n, err := strconv.Atoi(qOffset)
		if err != nil || n < 0 {
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("offset must be a non-negative integer"))
			return
		}
		offset = n
	}

	resp, err := c.service.List(ctx, tenantID, statusPtr, limit, offset)
	if err != nil {
		c.writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}

// Revoke maneja DELETE /v2/admin/tenants/{tenant_id}/invitations/{id}.
func (c *InvitationController) Revoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := strings.TrimSpace(r.PathValue("tenant_id"))
	if tenantID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant_id is required"))
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("id is required"))
		return
	}

	if err := c.service.Revoke(ctx, tenantID, id); err != nil {
		c.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *InvitationController) writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, svc.ErrInvalidInvitationEmail),
		errors.Is(err, svc.ErrInvitationInvalidStatus),
		errors.Is(err, svc.ErrInvitationAdminIDRequired):
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(err.Error()))
	case errors.Is(err, svc.ErrInvitationAlreadyHandled):
		httperrors.WriteError(w, httperrors.ErrConflict.WithDetail(err.Error()))
	default:
		httperrors.WriteError(w, mapTenantError(err))
	}
}
