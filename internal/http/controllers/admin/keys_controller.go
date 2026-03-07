package admin

import (
	"encoding/json"
	"net/http"
	"strings"

	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
)

type KeysController struct {
	service svc.KeysService
}

func NewKeysController(service svc.KeysService) *KeysController {
	return &KeysController{service: service}
}

// GET /v2/admin/keys?tenant_id=...
func (c *KeysController) ListKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := r.URL.Query().Get("tenant_id")

	keys, err := c.service.ListKeys(ctx, tenantID)
	if err != nil {
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

// GET /v2/admin/keys/{kid}
func (c *KeysController) GetKey(w http.ResponseWriter, r *http.Request) {
	kid := extractKIDFromPath(r.URL.Path)
	if kid == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("kid required"))
		return
	}

	ctx := r.Context()
	key, err := c.service.GetKey(ctx, kid)
	if err != nil {
		httperrors.WriteError(w, httperrors.ErrNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(key)
}

// POST /v2/admin/keys/rotate
func (c *KeysController) RotateKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.RotateKeysRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	if req.GraceSeconds <= 0 {
		req.GraceSeconds = 86400 // Default: 24 horas
	}

	result, err := c.service.RotateKeys(ctx, req.TenantID, req.GraceSeconds)
	if err != nil {
		httperrors.WriteError(w, httperrors.ErrInternalServerError.WithDetail(err.Error()))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// POST /v2/admin/keys/{kid}/revoke
func (c *KeysController) RevokeKey(w http.ResponseWriter, r *http.Request) {
	kid := extractKIDFromPath(r.URL.Path)
	if kid == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("kid required"))
		return
	}

	ctx := r.Context()
	if err := c.service.RevokeKey(ctx, kid); err != nil {
		httperrors.WriteError(w, httperrors.ErrInternalServerError.WithDetail(err.Error()))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func extractKIDFromPath(path string) string {
	// /v2/admin/keys/{kid} o /v2/admin/keys/{kid}/revoke
	parts := strings.Split(strings.TrimPrefix(path, "/v2/admin/keys/"), "/")
	if len(parts) > 0 && parts[0] != "" && parts[0] != "rotate" {
		return parts[0]
	}
	return ""
}
