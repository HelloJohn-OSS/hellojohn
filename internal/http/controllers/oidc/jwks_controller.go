// Package oidc contiene los controllers para endpoints OIDC/Discovery.
package oidc

import (
	"errors"
	"net/http"
	"strings"

	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/oidc"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// JWKSController maneja las rutas /.well-known/jwks
type JWKSController struct {
	service svc.JWKSService
}

// NewJWKSController crea un nuevo controller JWKS.
func NewJWKSController(service svc.JWKSService) *JWKSController {
	return &JWKSController{service: service}
}

// GetGlobal maneja GET/HEAD /.well-known/jwks.json
func (c *JWKSController) GetGlobal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("JWKSController.GetGlobal"))

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	setNoStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	data, err := c.service.GetGlobalJWKS(ctx)
	if err != nil {
		log.Error("failed to get global JWKS", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError.WithCause(err))
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// GetByTenant maneja GET/HEAD /.well-known/jwks/{slug}.json
func (c *JWKSController) GetByTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("JWKSController.GetByTenant"))

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Extraer slug del path
	slug := extractSlugFromJWKSPath(r.URL.Path)
	if slug == "" {
		httperrors.WriteError(w, httperrors.ErrNotFound)
		return
	}

	log = log.With(logger.TenantSlug(slug))

	setNoStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	data, err := c.service.GetTenantJWKS(ctx, slug)
	if err != nil {
		log.Error("failed to get tenant JWKS", logger.Err(err))
		httperrors.WriteError(w, mapJWKSError(err))
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// ─── Helpers ───

// extractSlugFromJWKSPath extrae el slug de /.well-known/jwks/{slug}.json
func extractSlugFromJWKSPath(path string) string {
	const prefix = "/.well-known/jwks/"
	const suffix = ".json"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return ""
	}
	slug := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	return strings.Trim(slug, "/")
}

func setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func mapJWKSError(err error) *httperrors.AppError {
	if errors.Is(err, svc.ErrInvalidSlug) {
		return httperrors.ErrBadRequest.WithDetail("invalid slug")
	}
	return httperrors.ErrInternalServerError.WithCause(err)
}
