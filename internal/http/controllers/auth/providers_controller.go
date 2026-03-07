package auth

import (
	"encoding/json"
	"net/http"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/auth"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// ProvidersController handles GET /v2/auth/providers.
type ProvidersController struct {
	service svc.ProvidersService
}

// NewProvidersController creates a new providers controller.
func NewProvidersController(service svc.ProvidersService) *ProvidersController {
	return &ProvidersController{service: service}
}

// GetProviders handles the providers discovery request.
// GET /v2/auth/providers?tenant_id=...&client_id=...&redirect_uri=...
func (c *ProvidersController) GetProviders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ProvidersController.GetProviders"))

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Parse query params
	q := r.URL.Query()
	req := dto.ProvidersRequest{
		TenantID:    q.Get("tenant_id"),
		ClientID:    q.Get("client_id"),
		RedirectURI: q.Get("redirect_uri"),
	}

	result, err := c.service.GetProviders(ctx, req)
	if err != nil {
		log.Error("providers discovery failed", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	// Build response
	resp := dto.ProvidersResponse{
		Providers: result.Providers,
	}

	// Security headers
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)

	log.Debug("providers returned")
}
