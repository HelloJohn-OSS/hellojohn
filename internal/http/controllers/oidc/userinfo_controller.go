package oidc

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/oidc"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// UserInfoController maneja el endpoint /userinfo
type UserInfoController struct {
	service svc.UserInfoService
}

// NewUserInfoController crea un nuevo controller de UserInfo.
func NewUserInfoController(service svc.UserInfoService) *UserInfoController {
	return &UserInfoController{service: service}
}

// GetUserInfo maneja GET/POST /userinfo
func (c *UserInfoController) GetUserInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("UserInfoController.GetUserInfo"))

	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Extraer bearer token
	bearerToken := extractBearerToken(r)
	if bearerToken == "" {
		writeOIDCAuthError(w, "userinfo", "invalid_token", "missing bearer token", http.StatusUnauthorized)
		return
	}

	resp, err := c.service.GetUserInfo(ctx, bearerToken)
	if err != nil {
		log.Debug("userinfo failed", logger.Err(err))
		writeOIDCAuthError(w, "userinfo", "invalid_token", mapUserInfoError(err), http.StatusUnauthorized)
		return
	}

	// Headers OIDC estándar
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Add("Vary", "Authorization")

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ─── Helpers ───

func extractBearerToken(r *http.Request) string {
	ah := strings.TrimSpace(r.Header.Get("Authorization"))
	if ah == "" || !strings.HasPrefix(strings.ToLower(ah), "bearer ") {
		return ""
	}
	return strings.TrimSpace(ah[len("Bearer "):])
}

func writeOIDCAuthError(w http.ResponseWriter, realm, errorCode, errorDesc string, status int) {
	w.Header().Set("WWW-Authenticate",
		`Bearer realm="`+realm+`", error="`+errorCode+`", error_description="`+errorDesc+`"`)
	httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail(errorDesc))
}

func mapUserInfoError(err error) string {
	switch {
	case errors.Is(err, svc.ErrMissingToken):
		return "missing bearer token"
	case errors.Is(err, svc.ErrInvalidToken):
		return "token invalid or expired"
	case errors.Is(err, svc.ErrIssuerMismatch):
		return "issuer mismatch"
	case errors.Is(err, svc.ErrMissingSub):
		return "missing sub claim"
	default:
		return "invalid_token"
	}
}
