package oauth

import (
	"encoding/json"
	"net/http"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/oauth"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	"github.com/dropDatabas3/hellojohn/internal/http/services/oauth"
)

type ConsentController struct {
	service oauth.ConsentService
}

func NewConsentController(service oauth.ConsentService) *ConsentController {
	return &ConsentController{
		service: service,
	}
}

// GetInfo retrieves consent info with scope DisplayNames for consent screen.
// GET /v2/auth/consent/info?consent_token=xxx
// ISS-05-03: DisplayName in Consent Screen
func (c *ConsentController) GetInfo(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("consent_token")
	if token == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("consent_token required"))
		return
	}

	res, err := c.service.GetInfo(r.Context(), token)
	if err != nil {
		switch err {
		case oauth.ErrConsentMissingToken, oauth.ErrConsentNotFound:
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(err.Error()))
		default:
			httperrors.WriteError(w, httperrors.ErrInternalServerError.WithCause(err))
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(res)
}

// Accept handles the consent decision (approve/reject).
// POST /v2/auth/consent/accept
func (c *ConsentController) Accept(w http.ResponseWriter, r *http.Request) {
	var req dto.ConsentAcceptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON.WithCause(err))
		return
	}

	res, err := c.service.Accept(r.Context(), req)
	if err != nil {
		// Map service errors to HTTP errors using V2 error variables
		switch err {
		case oauth.ErrConsentMissingToken, oauth.ErrConsentNotFound:
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(err.Error()))
		case oauth.ErrConsentStoreFailed, oauth.ErrConsentCodeFailed:
			httperrors.WriteError(w, httperrors.ErrInternalServerError.WithDetail(err.Error()))
		default:
			httperrors.WriteError(w, httperrors.ErrInternalServerError.WithCause(err))
		}
		return
	}

	// Success Redirect
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	http.Redirect(w, r, res.URL, http.StatusFound)
}
