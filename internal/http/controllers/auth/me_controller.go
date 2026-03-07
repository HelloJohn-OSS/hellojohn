package auth

import (
	"encoding/json"
	"net/http"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// MeController handles GET /v2/me.
type MeController struct{}

// NewMeController creates a new me controller.
func NewMeController() *MeController {
	return &MeController{}
}

// Me handles the request to get current user's claims.
// Requires authentication via Bearer token.
func (c *MeController) Me(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("MeController.Me"))

	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Get claims from context (set by RequireAuth middleware)
	claims := mw.GetClaims(ctx)
	if claims == nil {
		httperrors.WriteError(w, httperrors.ErrUnauthorized)
		return
	}

	// Build response with selected claims
	resp := dto.MeResponse{
		Sub:    claims["sub"],
		Tid:    claims["tid"],
		Aud:    claims["aud"],
		Amr:    claims["amr"],
		Custom: claims["custom"],
		Exp:    claims["exp"],
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)

	log.Debug("claims returned")
}
