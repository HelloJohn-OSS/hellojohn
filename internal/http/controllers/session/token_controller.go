package session

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/session"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/session"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// SessionTokenController handles POST /v2/session/token.
type SessionTokenController struct {
	service svc.SessionTokenService
	config  dto.LoginConfig
}

// NewSessionTokenController creates a new session token controller.
func NewSessionTokenController(service svc.SessionTokenService, config dto.LoginConfig) *SessionTokenController {
	return &SessionTokenController{
		service: service,
		config:  config,
	}
}

// Mint exchanges an active session cookie for a short-lived JWT session token.
func (c *SessionTokenController) Mint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("SessionTokenController.Mint"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	cookieName := strings.TrimSpace(c.config.CookieName)
	if cookieName == "" {
		cookieName = "sid"
	}

	ck, err := r.Cookie(cookieName)
	if err != nil || ck == nil || strings.TrimSpace(ck.Value) == "" {
		httperrors.WriteError(w, httperrors.ErrSessionNotFound)
		return
	}

	result, err := c.service.MintFromSession(ctx, ck.Value)
	if err != nil {
		switch {
		case errors.Is(err, svc.ErrSessionTokenMissingSession),
			errors.Is(err, svc.ErrSessionTokenNotFound),
			errors.Is(err, svc.ErrSessionTokenInvalidSession),
			errors.Is(err, svc.ErrSessionTokenExpired):
			httperrors.WriteError(w, httperrors.ErrSessionExpired)
		default:
			log.Error("session token mint failed", logger.Err(err))
			httperrors.WriteError(w, httperrors.ErrInternalServerError)
		}
		return
	}

	resp := dto.SessionTokenResponse{
		Token:     result.Token,
		ExpiresIn: result.ExpiresIn,
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
