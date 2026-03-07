package admin

import (
	"encoding/json"
	"errors"
	"net/http"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

type APIKeyController struct {
	service svc.APIKeyService
}

func NewAPIKeyController(service svc.APIKeyService) *APIKeyController {
	return &APIKeyController{service: service}
}

// List → GET /v2/admin/api-keys
func (c *APIKeyController) List(w http.ResponseWriter, r *http.Request) {
	keys, err := c.service.List(r.Context())
	if err != nil {
		logger.From(r.Context()).Error("api_key list", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": keys})
}

// Get → GET /v2/admin/api-keys/{id}
func (c *APIKeyController) Get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	key, err := c.service.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, svc.ErrAPIKeyNotFound) {
			httperrors.WriteError(w, httperrors.ErrNotFound)
			return
		}
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": key})
}

// Create → POST /v2/admin/api-keys
func (c *APIKeyController) Create(w http.ResponseWriter, r *http.Request) {
	var req dto.CreateAPIKeyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	// Obtain caller identity from JWT claims. The nil-check is safe:
	// authentication is enforced at the middleware layer before this handler runs.
	// adminClaims may be nil in test contexts or when using API key auth (where
	// GetAdminClaims returns nil); in that case createdBy is left empty.
	adminClaims := mw.GetAdminClaims(r.Context())
	createdBy := ""
	if adminClaims != nil {
		createdBy = adminClaims.Email
	}

	result, err := c.service.Create(r.Context(), req, createdBy)
	if err != nil {
		c.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"data": result})
}

// Revoke → DELETE /v2/admin/api-keys/{id}
func (c *APIKeyController) Revoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := c.service.Revoke(r.Context(), id); err != nil {
		if errors.Is(err, svc.ErrAPIKeyNotFound) {
			httperrors.WriteError(w, httperrors.ErrNotFound)
			return
		}
		logger.From(r.Context()).Error("api_key revoke", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Rotate → POST /v2/admin/api-keys/{id}/rotate
func (c *APIKeyController) Rotate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	adminClaims := mw.GetAdminClaims(r.Context())
	createdBy := ""
	if adminClaims != nil {
		createdBy = adminClaims.Email
	}

	result, err := c.service.Rotate(r.Context(), id, createdBy)
	if err != nil {
		c.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": result})
}

func (c *APIKeyController) writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, svc.ErrAPIKeyNotFound):
		httperrors.WriteError(w, httperrors.ErrNotFound)
	case errors.Is(err, svc.ErrAPIKeyInvalidScope):
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invalid scope"))
	case errors.Is(err, svc.ErrAPIKeyNameEmpty):
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("name is required"))
	case errors.Is(err, svc.ErrAPIKeyNameTooLong):
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("name too long (max 100 chars)"))
	default:
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
	}
}
