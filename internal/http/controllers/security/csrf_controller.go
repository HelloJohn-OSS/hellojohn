package security

import (
	"encoding/json"
	"net/http"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/security"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/security"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// CSRFController handles GET /v2/csrf.
type CSRFController struct {
	service svc.CSRFService
}

// NewCSRFController creates a new CSRF controller.
func NewCSRFController(service svc.CSRFService) *CSRFController {
	return &CSRFController{service: service}
}

// GetToken handles the CSRF token generation request.
// Sets a cookie with the token and returns it in JSON body (double-submit pattern).
func (c *CSRFController) GetToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("CSRFController.GetToken"))

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	result, err := c.service.GenerateToken(ctx)
	if err != nil {
		log.Error("failed to generate CSRF token", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	// Set cookie (non-HttpOnly by design so frontend can read it for double-submit)
	http.SetCookie(w, &http.Cookie{
		Name:     result.CookieName,
		Value:    result.Token,
		Path:     "/",
		HttpOnly: false, // Intentional: frontend needs to read and send in header
		Secure:   result.Secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  result.ExpiresAt,
	})

	// Set anti-cache headers
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// Return token in JSON body
	resp := dto.CSRFResponse{
		CSRFToken: result.Token,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)

	log.Debug("csrf token issued")
}
