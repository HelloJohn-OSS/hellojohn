package oauth

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/oauth"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/oauth"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"go.uber.org/zap"
)

const maxRevokeBodySize = 32 * 1024 // 32KB

// RevokeController handles POST /oauth2/revoke.
type RevokeController struct {
	service svc.RevokeService
}

// NewRevokeController creates a new revoke controller.
func NewRevokeController(service svc.RevokeService) *RevokeController {
	return &RevokeController{service: service}
}

// Revoke handles the token revocation request.
// Accepts token via form, Bearer header, or JSON body.
// Always returns 200 OK per RFC 7009 (idempotent).
func (c *RevokeController) Revoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("RevokeController.Revoke"))

	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Limit body size
	r.Body = http.MaxBytesReader(w, r.Body, maxRevokeBodySize)
	defer r.Body.Close()

	// Extract token from multiple sources
	token := c.extractToken(r, log)
	if token == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("token is required"))
		return
	}

	// Revoke the token (idempotent - always succeeds)
	if err := c.service.Revoke(ctx, token); err != nil {
		if err == svc.ErrRevokeTokenEmpty {
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("token is required"))
			return
		}
		// For any other error, still return 200 (non-filtering per RFC 7009)
		log.Debug("revoke error suppressed", logger.Err(err))
	}

	// RFC 7009: Always return 200 OK with no-store headers
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)

	log.Debug("token revocation completed")
}

// extractToken extracts token from form, Bearer header, or JSON body.
func (c *RevokeController) extractToken(r *http.Request, log *zap.Logger) string {
	// Try 1: x-www-form-urlencoded
	if err := r.ParseForm(); err == nil {
		if token := strings.TrimSpace(r.PostForm.Get("token")); token != "" {
			log.Debug("token from form data")
			return token
		}
	}

	// Try 2: Authorization: Bearer <token>
	if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
		if token := strings.TrimSpace(h[len("Bearer "):])[:]; token != "" {
			log.Debug("token from bearer header")
			return token
		}
	}

	// Try 3: JSON body {"token": "..."}
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(contentType, "application/json") {
		var body dto.RevokeRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, maxRevokeBodySize)).Decode(&body); err == nil {
			if token := strings.TrimSpace(body.Token); token != "" {
				log.Debug("token from json body")
				return token
			}
		}
	}

	return ""
}
