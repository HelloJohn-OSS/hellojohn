package middlewares

import (
	"log"
	"net/http"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/http/errors"
	storev2 "github.com/dropDatabas3/hellojohn/internal/store"
)

// =================================================================================
// TENANT RESOLVER
// =================================================================================

// TenantResolver define cómo obtener el tenant slug de un request.
type TenantResolver func(r *http.Request) string

// HeaderTenantResolver resuelve usando un header específico.
func HeaderTenantResolver(headerName string) TenantResolver {
	if headerName == "" {
		headerName = "X-Tenant-ID"
	}
	return func(r *http.Request) string {
		return strings.TrimSpace(r.Header.Get(headerName))
	}
}

// QueryTenantResolver resuelve usando un query parameter.
func QueryTenantResolver(paramName string) TenantResolver {
	if paramName == "" {
		paramName = "tenant"
	}
	return func(r *http.Request) string {
		return strings.TrimSpace(r.URL.Query().Get(paramName))
	}
}

// SubdomainTenantResolver resuelve desde el subdominio.
// Ej: acme.hellojohn.com -> "acme"
func SubdomainTenantResolver() TenantResolver {
	return func(r *http.Request) string {
		host := r.Host
		// Remover puerto si existe
		if i := strings.Index(host, ":"); i > 0 {
			host = host[:i]
		}
		// Si hay más de un punto, el primer segmento es el subdominio
		if strings.Count(host, ".") > 1 {
			parts := strings.Split(host, ".")
			return parts[0]
		}
		return ""
	}
}

// PathValueTenantResolver resuelve usando un path parameter del router.
// Ej: /v2/admin/tenants/{id}/sessions -> extrae "id" del path
func PathValueTenantResolver(paramName string) TenantResolver {
	if paramName == "" {
		paramName = "id"
	}
	return func(r *http.Request) string {
		return strings.TrimSpace(r.PathValue(paramName))
	}
}

// ChainResolvers combina múltiples resolvers, retornando el primer resultado no vacío.
func ChainResolvers(resolvers ...TenantResolver) TenantResolver {
	return func(r *http.Request) string {
		for _, resolver := range resolvers {
			if slug := resolver(r); slug != "" {
				return slug
			}
		}
		return ""
	}
}

// =================================================================================
// TENANT MIDDLEWARE
// =================================================================================

// TenantMiddleware inyecta el TenantDataAccess en el contexto.
type TenantMiddleware struct {
	manager  storev2.DataAccessLayer
	resolver TenantResolver
	optional bool // Si es true, no falla si no hay tenant
}

// TenantMiddlewareConfig configura el middleware de tenant.
type TenantMiddlewareConfig struct {
	Manager  storev2.DataAccessLayer
	Resolver TenantResolver
	Optional bool // Si es true, no falla si no hay tenant
}

// NewTenantMiddleware crea un nuevo middleware de tenant.
// Si resolver es nil, usa la cadena: PathValue -> Header -> Query -> Subdomain
func NewTenantMiddleware(cfg TenantMiddlewareConfig) *TenantMiddleware {
	resolver := cfg.Resolver
	if resolver == nil {
		resolver = ChainResolvers(
			PathValueTenantResolver("id"), // Para rutas como /v2/admin/tenants/{id}/...
			HeaderTenantResolver("X-Tenant-ID"),
			HeaderTenantResolver("X-Tenant-Slug"),
			QueryTenantResolver("tenant"),
			QueryTenantResolver("tenant_id"),
			SubdomainTenantResolver(),
		)
	}
	return &TenantMiddleware{
		manager:  cfg.Manager,
		resolver: resolver,
		optional: cfg.Optional,
	}
}

// Handle intercepta el request, resuelve el tenant y carga el DataAccess.
func (m *TenantMiddleware) Handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slug := m.resolver(r)

		if slug == "" {
			if m.optional {
				next.ServeHTTP(w, r)
				return
			}
			errors.WriteError(w, errors.ErrBadRequest.WithDetail("missing tenant identifier"))
			return
		}

		if m.manager == nil {
			if m.optional {
				next.ServeHTTP(w, r)
				return
			}
			errors.WriteError(w, errors.ErrServiceUnavailable.WithDetail("tenant DAL not configured"))
			return
		}

		// Obtener Data Access desde Store V2
		// El DAL tiene cache interno, por lo que esta llamada es rápida.
		tda, err := m.manager.ForTenant(r.Context(), slug)
		if err != nil {
			log.Printf(`{"level":"warn","msg":"tenant_load_error","slug":"%s","err":"%v"}`, slug, err)
			if m.optional {
				next.ServeHTTP(w, r)
				return
			}
			errors.WriteError(w, errors.ErrTenantNotFound.WithDetail(slug))
			return
		}

		// Inyectar en contexto usando el helper unificado
		ctx := WithTenant(r.Context(), tda)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// =================================================================================
// HELPER MIDDLEWARE FUNCTION
// =================================================================================

// WithTenantResolution crea un middleware funcional para resolución de tenant.
// Más simple que TenantMiddleware para casos básicos.
func WithTenantResolution(dal storev2.DataAccessLayer, optional bool) Middleware {
	mw := NewTenantMiddleware(TenantMiddlewareConfig{
		Manager:  dal,
		Optional: optional,
	})
	return mw.Handle
}

// RequireTenant verifica que haya un tenant en el contexto.
// Debe usarse después de WithTenantResolution.
func RequireTenant() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if GetTenant(r.Context()) == nil {
				errors.WriteError(w, errors.ErrBadRequest.WithDetail("tenant required"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireTenantDB verifica que el tenant tenga base de datos configurada.
func RequireTenantDB() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tda := GetTenant(r.Context())
			if tda == nil {
				log.Printf(`{"level":"warn","msg":"tenant_db_check_failed","reason":"no_tenant_in_context","path":"%s"}`, r.URL.Path)
				errors.WriteError(w, errors.ErrBadRequest.WithDetail("tenant required"))
				return
			}
			if !tda.HasDB() {
				log.Printf(`{"level":"warn","msg":"tenant_db_check_failed","reason":"no_db_configured","tenant":"%s","path":"%s"}`, tda.Slug(), r.URL.Path)
				errors.WriteError(w, errors.ErrTenantNoDatabase.WithDetail("tenant has no database configured"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
