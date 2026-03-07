package social

import (
	"encoding/json"
	"net/http"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/social"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/social"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// ExchangeController handles POST /v2/auth/social/exchange.
type ExchangeController struct {
	service svc.ExchangeService
}

// NewExchangeController creates a new social exchange controller.
func NewExchangeController(service svc.ExchangeService) *ExchangeController {
	return &ExchangeController{service: service}
}

// Exchange handles the social login code exchange request.
// Returns tokens for a valid one-shot login code.
func (c *ExchangeController) Exchange(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ExchangeController.Exchange"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Limit body size
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10) // 32KB

	// Parse request
	var req dto.ExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invalid JSON"))
		return
	}

	// Call service
	result, err := c.service.Exchange(ctx, req)
	if err != nil {
		switch err {
		case svc.ErrCodeMissing, svc.ErrClientMissing:
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("missing required parameters"))
		case svc.ErrCodeNotFound:
			httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("code not found or expired"))
		case svc.ErrClientMismatch:
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("client_id mismatch"))
		case svc.ErrTenantMismatch:
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant_id mismatch"))
		case svc.ErrPayloadInvalid:
			httperrors.WriteError(w, httperrors.ErrInternalServerError)
		default:
			log.Error("exchange error", logger.Err(err))
			httperrors.WriteError(w, httperrors.ErrInternalServerError)
		}
		return
	}

	// Set anti-cache headers
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// Return tokens
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(result.Response)

	log.Debug("social code exchanged")
}
