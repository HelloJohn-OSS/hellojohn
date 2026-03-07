package oidc

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/oidc"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// DiscoveryController maneja las rutas /.well-known/openid-configuration
type DiscoveryController struct {
	service svc.DiscoveryService
}

// NewDiscoveryController crea un nuevo controller de OIDC Discovery.
func NewDiscoveryController(service svc.DiscoveryService) *DiscoveryController {
	return &DiscoveryController{service: service}
}

// GetGlobal maneja GET/HEAD /.well-known/openid-configuration
func (c *DiscoveryController) GetGlobal(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("DiscoveryController.GetGlobal"))

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	meta := c.service.GetGlobalDiscovery(ctx)

	// Cache razonable para discovery global
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=600, must-revalidate")
	w.Header().Set("Expires", time.Now().Add(10*time.Minute).UTC().Format(http.TimeFormat))

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Debug("serving global OIDC discovery")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(meta)
}

// GetByTenant maneja GET/HEAD /t/{slug}/.well-known/openid-configuration
func (c *DiscoveryController) GetByTenant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("DiscoveryController.GetByTenant"))

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
		return
	}

	// Extraer slug del path
	slug := extractSlugFromDiscoveryPath(r.URL.Path)
	if slug == "" {
		httperrors.WriteError(w, httperrors.ErrNotFound)
		return
	}

	log = log.With(logger.TenantSlug(slug))

	meta, err := c.service.GetTenantDiscovery(ctx, slug)
	if err != nil {
		log.Error("failed to get tenant discovery", logger.Err(err))
		httperrors.WriteError(w, mapDiscoveryError(err))
		return
	}

	// No-store para per-tenant (cambios de issuer/jwks por rotación)
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Debug("serving tenant OIDC discovery")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(meta)
}

// ─── Helpers ───

// extractSlugFromDiscoveryPath extrae el slug de /t/{slug}/.well-known/openid-configuration
func extractSlugFromDiscoveryPath(path string) string {
	const prefix = "/t/"
	const suffix = "/.well-known/openid-configuration"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return ""
	}
	slug := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	return strings.Trim(slug, "/")
}

func mapDiscoveryError(err error) *httperrors.AppError {
	switch {
	case errors.Is(err, svc.ErrInvalidTenantSlug):
		return httperrors.ErrBadRequest.WithDetail("invalid tenant slug")
	case errors.Is(err, svc.ErrTenantNotFound):
		return httperrors.ErrNotFound.WithDetail("tenant not found")
	default:
		return httperrors.ErrInternalServerError.WithCause(err)
	}
}
