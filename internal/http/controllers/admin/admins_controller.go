package admin

import (
	"encoding/json"
	"errors"
	"net/http"

	cp "github.com/dropDatabas3/hellojohn/internal/controlplane"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
)

// AdminsController maneja las operaciones CRUD de admin accounts.
type AdminsController struct {
	service svc.AdminsService
}

// NewAdminsController crea un AdminsController.
func NewAdminsController(service svc.AdminsService) *AdminsController {
	return &AdminsController{service: service}
}

// List retorna todos los admin accounts.
// GET /v2/admin/admins
func (c *AdminsController) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	admins, err := c.service.List(ctx)
	if err != nil {
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dto.AdminListResponse{
		Admins: admins,
		Total:  len(admins),
	})
}

// Get retorna un admin por ID.
// GET /v2/admin/admins/{id}
func (c *AdminsController) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	if id == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("id required"))
		return
	}

	admin, err := c.service.Get(ctx, id)
	if err != nil {
		c.writeErr(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(admin)
}

// Create crea un nuevo admin (o envía invite).
// POST /v2/admin/admins
func (c *AdminsController) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get caller ID from JWT
	claims := mw.GetAdminClaims(ctx)
	if claims == nil {
		httperrors.WriteError(w, httperrors.ErrUnauthorized)
		return
	}
	callerID := claims.AdminID

	var req dto.CreateAdminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	admin, inviteLink, err := c.service.Create(ctx, callerID, req)
	if err != nil {
		c.writeErr(w, err)
		return
	}

	resp := map[string]any{"admin": admin}
	if inviteLink != "" {
		resp["invite_link"] = inviteLink
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// Update actualiza un admin existente.
// PUT /v2/admin/admins/{id}
func (c *AdminsController) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	if id == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("id required"))
		return
	}

	var req dto.UpdateAdminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	admin, err := c.service.Update(ctx, id, req)
	if err != nil {
		c.writeErr(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(admin)
}

// Delete elimina un admin.
// DELETE /v2/admin/admins/{id}
func (c *AdminsController) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	claims := mw.GetAdminClaims(ctx)
	if claims == nil {
		httperrors.WriteError(w, httperrors.ErrUnauthorized)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("id required"))
		return
	}

	if err := c.service.Delete(ctx, claims.AdminID, id); err != nil {
		c.writeErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Disable deshabilita un admin.
// POST /v2/admin/admins/{id}/disable
func (c *AdminsController) Disable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	claims := mw.GetAdminClaims(ctx)
	if claims == nil {
		httperrors.WriteError(w, httperrors.ErrUnauthorized)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("id required"))
		return
	}

	if err := c.service.Disable(ctx, claims.AdminID, id); err != nil {
		c.writeErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Enable habilita un admin deshabilitado.
// POST /v2/admin/admins/{id}/enable
func (c *AdminsController) Enable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := r.PathValue("id")
	if id == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("id required"))
		return
	}

	if err := c.service.Enable(ctx, id); err != nil {
		c.writeErr(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ValidateInvite valida un invite token (público).
// GET /v2/admin/auth/accept-invite?token=...
func (c *AdminsController) ValidateInvite(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rawToken := r.URL.Query().Get("token")
	if rawToken == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("token required"))
		return
	}

	resp, err := c.service.ValidateInvite(ctx, rawToken)
	if err != nil {
		c.writeErr(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// AcceptInvite acepta el invite y establece contraseña (público).
// POST /v2/admin/auth/accept-invite
func (c *AdminsController) AcceptInvite(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.AcceptInviteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	admin, err := c.service.AcceptInvite(ctx, req)
	if err != nil {
		c.writeErr(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(admin)
}

// writeErr mapea errores de service a respuestas HTTP.
func (c *AdminsController) writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, cp.ErrAdminNotFound):
		httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("admin not found"))
	case errors.Is(err, svc.ErrAdminSelfDelete):
		httperrors.WriteError(w, httperrors.ErrForbidden.WithDetail("cannot delete your own account"))
	case errors.Is(err, svc.ErrAdminSelfDisable):
		httperrors.WriteError(w, httperrors.ErrForbidden.WithDetail("cannot disable your own account"))
	case errors.Is(err, svc.ErrInviteExpired):
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invite token expired"))
	case errors.Is(err, svc.ErrInviteInvalid):
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invalid or already used invite token"))
	case errors.Is(err, svc.ErrWeakPassword):
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("password must be at least 8 characters"))
	default:
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
	}
}
