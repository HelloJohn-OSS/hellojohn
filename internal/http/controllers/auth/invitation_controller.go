package auth

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/auth"
)

const maxInvitationAcceptBodySize = 64 * 1024 // 64KB

// InvitationAcceptController maneja POST /v2/auth/invitations/accept.
type InvitationAcceptController struct {
	service svc.InvitationAcceptService
}

// NewInvitationAcceptController crea un InvitationAcceptController.
func NewInvitationAcceptController(service svc.InvitationAcceptService) *InvitationAcceptController {
	return &InvitationAcceptController{service: service}
}

// Accept maneja la aceptacion publica de invitaciones.
func (c *InvitationAcceptController) Accept(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	ctx := r.Context()
	tenantSlug := strings.TrimSpace(r.Header.Get("X-Tenant-ID"))
	if tenantSlug == "" {
		tenantSlug = strings.TrimSpace(r.PathValue("tenant_id"))
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxInvitationAcceptBodySize)
	defer r.Body.Close()

	var req dto.AcceptInvitationRequest
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

	result, err := c.service.Accept(ctx, tenantSlug, req)
	if err != nil {
		c.writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(result)
}

func (c *InvitationAcceptController) writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, svc.ErrInvitationTenantRequired),
		errors.Is(err, svc.ErrInvitationTokenRequired),
		errors.Is(err, svc.ErrInvitationPasswordRequired):
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(err.Error()))
	case errors.Is(err, svc.ErrInvitationInvalid):
		httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail(err.Error()))
	case errors.Is(err, svc.ErrInvitationAlreadyUsed):
		httperrors.WriteError(w, httperrors.ErrConflict.WithDetail(err.Error()))
	case errors.Is(err, svc.ErrInvitationExpired):
		httperrors.WriteError(w, httperrors.ErrUnprocessableEntity.WithDetail(err.Error()))
	case errors.Is(err, svc.ErrInvitationNoClient):
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail(err.Error()))
	case errors.Is(err, svc.ErrInvitationCreateFailed):
		httperrors.WriteError(w, httperrors.ErrConflict.WithDetail(err.Error()))
	case errors.Is(err, svc.ErrInvitationTokenIssueFailed):
		httperrors.WriteError(w, httperrors.ErrInternalServerError.WithDetail(err.Error()))
	default:
		httperrors.WriteError(w, httperrors.FromError(err))
	}
}
