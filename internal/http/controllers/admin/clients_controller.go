// Package admin contiene controllers para endpoints administrativos.
package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/controlplane"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// ClientsController maneja las rutas /v2/admin/clients
type ClientsController struct {
	service svc.ClientService
}

// NewClientsController crea un nuevo controller de clients.
func NewClientsController(service svc.ClientService) *ClientsController {
	return &ClientsController{service: service}
}

// ListClients maneja GET /v2/admin/clients
func (c *ClientsController) ListClients(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(
		logger.Layer("controller"),
		logger.Op("ClientsController.ListClients"),
	)

	// El tenant viene del middleware
	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant required"))
		return
	}

	log = log.With(logger.TenantSlug(tda.Slug()))

	clients, err := c.service.List(ctx, tda.Slug())
	if err != nil {
		log.Error("list failed", logger.Err(err))
		httperrors.WriteError(w, mapError(err))
		return
	}

	resp := make([]dto.ClientResponse, 0, len(clients))
	for _, cl := range clients {
		resp = append(resp, toClientResponse(cl))
	}

	writeJSON(w, http.StatusOK, resp)
}

func (c *ClientsController) GetClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(
		logger.Layer("controller"),
		logger.Op("ClientsController.GetClient"),
	)

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant required"))
		return
	}

	clientID := r.PathValue("clientId")
	if clientID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("missing client_id"))
		return
	}

	log = log.With(logger.TenantSlug(tda.Slug()), logger.ClientID(clientID))

	client, err := c.service.Get(ctx, tda.Slug(), clientID)
	if err != nil {
		log.Error("get failed", logger.Err(err))
		httperrors.WriteError(w, mapError(err))
		return
	}

	writeJSON(w, http.StatusOK, toClientResponse(*client))
}

// CreateClient maneja POST /v2/admin/clients
func (c *ClientsController) CreateClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(
		logger.Layer("controller"),
		logger.Op("ClientsController.CreateClient"),
	)

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant required"))
		return
	}

	log = log.With(logger.TenantSlug(tda.Slug()))

	var req dto.ClientRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	input := toClientInput(req)

	client, err := c.service.Create(ctx, tda.Slug(), input)
	if err != nil {
		log.Error("create failed", logger.Err(err))
		httperrors.WriteError(w, mapError(err))
		return
	}

	log.Info("client created", logger.ClientID(client.ClientID))
	writeJSON(w, http.StatusCreated, toClientResponse(*client))
}

// UpdateClient maneja PUT/PATCH /v2/admin/clients/{clientId}
func (c *ClientsController) UpdateClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(
		logger.Layer("controller"),
		logger.Op("ClientsController.UpdateClient"),
	)

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant required"))
		return
	}

	// Extraer clientId del path
	clientID := r.PathValue("clientId")
	if clientID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("missing client_id"))
		return
	}

	log = log.With(logger.TenantSlug(tda.Slug()), logger.ClientID(clientID))

	var req dto.ClientRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	// Forzar el clientId del path (comportamiento V1)
	req.ClientID = clientID
	input := toClientInput(req)

	client, err := c.service.Update(ctx, tda.Slug(), input)
	if err != nil {
		log.Error("update failed", logger.Err(err))
		httperrors.WriteError(w, mapError(err))
		return
	}

	log.Info("client updated")
	writeJSON(w, http.StatusOK, toClientResponse(*client))
}

// DeleteClient maneja DELETE /v2/admin/clients/{clientId}
func (c *ClientsController) DeleteClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(
		logger.Layer("controller"),
		logger.Op("ClientsController.DeleteClient"),
	)

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant required"))
		return
	}

	clientID := r.PathValue("clientId")
	if clientID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("missing client_id"))
		return
	}

	log = log.With(logger.TenantSlug(tda.Slug()), logger.ClientID(clientID))

	if err := c.service.Delete(ctx, tda.Slug(), clientID); err != nil {
		log.Error("delete failed", logger.Err(err))
		httperrors.WriteError(w, mapError(err))
		return
	}

	log.Info("client deleted")
	w.WriteHeader(http.StatusNoContent)
}

// RevokeSecret maneja POST /v2/admin/clients/{clientId}/revoke
func (c *ClientsController) RevokeSecret(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(
		logger.Layer("controller"),
		logger.Op("ClientsController.RevokeSecret"),
	)

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant required"))
		return
	}

	// Extract clientId from path: /v2/admin/tenants/{tenant_id}/clients/{clientId}/revoke-secret
	clientID := r.PathValue("clientId")
	if clientID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("missing client_id"))
		return
	}

	log = log.With(logger.TenantSlug(tda.Slug()), logger.ClientID(clientID))

	// Call service to revoke secret and get new plaintext secret
	newSecret, err := c.service.RevokeSecret(ctx, tda.Slug(), clientID)
	if err != nil {
		log.Error("revoke secret failed", logger.Err(err))
		httperrors.WriteError(w, mapError(err))
		return
	}

	log.Info("client secret revoked", logger.ClientID(clientID))

	// Return new secret (ONLY TIME IT'S SHOWN)
	writeJSON(w, http.StatusOK, dto.RevokeClientSecretResponse{
		ClientID:  clientID,
		NewSecret: newSecret,
		Message:   "Client secret rotated successfully. Save this secret - it won't be shown again.",
	})
}

// ─── Helpers ───

func toClientInput(req dto.ClientRequest) controlplane.ClientInput {
	return controlplane.ClientInput{
		Name:                     req.Name,
		ClientID:                 req.ClientID,
		Type:                     req.Type,
		AuthProfile:              req.AuthProfile,
		RedirectURIs:             req.RedirectURIs,
		AllowedOrigins:           req.AllowedOrigins,
		Providers:                req.Providers,
		Scopes:                   req.Scopes,
		Secret:                   req.Secret,
		RequireEmailVerification: req.RequireEmailVerification,
		ResetPasswordURL:         req.ResetPasswordURL,
		VerifyEmailURL:           req.VerifyEmailURL,
		// Campos adicionales OAuth2/OIDC
		GrantTypes:      req.GrantTypes,
		AccessTokenTTL:  req.AccessTokenTTL,
		RefreshTokenTTL: req.RefreshTokenTTL,
		IDTokenTTL:      req.IDTokenTTL,
		PostLogoutURIs:  req.PostLogoutURIs,
		Description:     req.Description,
	}
}

func toClientResponse(cl repository.Client) dto.ClientResponse {
	resp := dto.ClientResponse{
		ID:                       cl.ID,
		Name:                     cl.Name,
		ClientID:                 cl.ClientID,
		Type:                     cl.Type,
		AuthProfile:              cl.AuthProfile,
		RedirectURIs:             cl.RedirectURIs,
		AllowedOrigins:           cl.AllowedOrigins,
		Providers:                cl.Providers,
		Scopes:                   cl.Scopes,
		RequireEmailVerification: cl.RequireEmailVerification,
		ResetPasswordURL:         cl.ResetPasswordURL,
		VerifyEmailURL:           cl.VerifyEmailURL,
		// Campos adicionales OAuth2/OIDC
		GrantTypes:      cl.GrantTypes,
		AccessTokenTTL:  cl.AccessTokenTTL,
		RefreshTokenTTL: cl.RefreshTokenTTL,
		IDTokenTTL:      cl.IDTokenTTL,
		PostLogoutURIs:  cl.PostLogoutURIs,
		Description:     cl.Description,
		// CreatedAt/UpdatedAt no existen en repository.Client, se omiten
	}

	// PlainSecret is only populated when the secret was just generated (one-time transport).
	// It is never persisted — SecretEnc always holds the encrypted value.
	if cl.PlainSecret != "" {
		resp.Secret = cl.PlainSecret // Plaintext secret — one-time, never persisted
	} else {
		resp.SecretHash = cl.SecretEnc // Encrypted hash (normal reads)
	}

	return resp
}

func mapError(err error) *httperrors.AppError {
	switch {
	case errors.Is(err, controlplane.ErrInvalidAuthProfile):
		return httperrors.New(http.StatusUnprocessableEntity, "INVALID_AUTH_PROFILE", "Invalid auth profile")
	case isNotFound(err):
		return httperrors.ErrNotFound.WithDetail(err.Error())
	case isConflict(err):
		return httperrors.ErrConflict.WithDetail(err.Error())
	case isBadInput(err):
		return httperrors.ErrBadRequest.WithDetail(err.Error())
	default:
		return httperrors.ErrInternalServerError
	}
}

func isNotFound(err error) bool {
	if errors.Is(err, repository.ErrNotFound) {
		return true
	}
	return strings.Contains(err.Error(), "not found")
}

func isConflict(err error) bool {
	return strings.Contains(err.Error(), "conflict") || strings.Contains(err.Error(), "already exists")
}

func isBadInput(err error) bool {
	return strings.Contains(err.Error(), "bad input") || strings.Contains(err.Error(), "required")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
