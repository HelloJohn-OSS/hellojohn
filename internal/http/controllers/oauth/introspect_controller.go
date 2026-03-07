package oauth

import (
	"encoding/json"
	"net/http"
	"strings"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/oauth"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/oauth"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"go.uber.org/zap"
)

// ClientAuthenticator validates client authentication.
type ClientAuthenticator interface {
	ValidateClientAuth(r *http.Request) (tenantID string, clientID string, ok bool)
}

// IntrospectController handles POST /oauth2/introspect.
type IntrospectController struct {
	service    svc.IntrospectService
	clientAuth ClientAuthenticator
}

// NewIntrospectController creates a new introspect controller.
func NewIntrospectController(service svc.IntrospectService, clientAuth ClientAuthenticator) *IntrospectController {
	return &IntrospectController{
		service:    service,
		clientAuth: clientAuth,
	}
}

// Introspect handles the token introspection request (RFC 7662).
// Requires client authentication via Basic Auth.
// Always returns 200 OK with active=true/false.
func (c *IntrospectController) Introspect(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("IntrospectController.Introspect"))

	// Set cache headers first
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Validate client authentication
	if c.clientAuth != nil {
		if _, _, ok := c.clientAuth.ValidateClientAuth(r); !ok {
			httperrors.WriteError(w, httperrors.ErrUnauthorized.WithDetail("invalid client credentials"))
			return
		}
	}

	// Parse form
	if err := r.ParseForm(); err != nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invalid form data"))
		return
	}

	token := strings.TrimSpace(r.PostForm.Get("token"))
	if token == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("token is required"))
		return
	}

	// Check include_sys flag
	includeSys := false
	if v := r.URL.Query().Get("include_sys"); v == "1" || strings.EqualFold(v, "true") {
		includeSys = true
	}

	// Call service
	result, err := c.service.Introspect(ctx, token, includeSys)
	if err != nil {
		if err == svc.ErrIntrospectTokenEmpty {
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("token is required"))
			return
		}
		// For any error, return inactive (don't leak info)
		log.Debug("introspect error", logger.Err(err))
		c.writeInactiveResponse(w)
		return
	}

	// Build response
	resp := c.buildResponse(result)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)

	log.Debug("introspection completed", zap.Bool("active", result.Active))
}

// writeInactiveResponse writes a simple inactive response.
func (c *IntrospectController) writeInactiveResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(dto.IntrospectResponse{Active: false})
}

// buildResponse builds the HTTP response from service result.
func (c *IntrospectController) buildResponse(result *dto.IntrospectResult) dto.IntrospectResponse {
	resp := dto.IntrospectResponse{
		Active:    result.Active,
		TokenType: result.TokenType,
		Sub:       result.Sub,
		ClientID:  result.ClientID,
		Scope:     result.Scope,
		Exp:       result.Exp,
		Iat:       result.Iat,
		Iss:       result.Iss,
		Jti:       result.Jti,
		Tid:       result.Tid,
		Acr:       result.Acr,
	}

	if len(result.Amr) > 0 {
		resp.Amr = result.Amr
	}

	if len(result.Roles) > 0 {
		resp.Roles = result.Roles
	}

	if len(result.Perms) > 0 {
		resp.Perms = result.Perms
	}

	return resp
}
