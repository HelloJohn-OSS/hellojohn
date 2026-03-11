package router

import (
	"net/http"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
)

// RegisterTenantAdminRoutes registra rutas de administración de tenants usando
// path parameters tipados de Go 1.22 (r.PathValue).
// tenant_id puede ser slug ("acme") o UUID — DAL.ForTenant resuelve ambos.
func RegisterTenantAdminRoutes(mux *http.ServeMux, deps AdminRouterDeps) {
	if deps.Controllers.Tenants == nil {
		return
	}

	c := deps.Controllers.Tenants
	collectionChain := sysAdminBaseChain(deps.Issuer, deps.RateLimiter, deps.AdminConfig, deps.APIKeyRepo)
	tenantChain := adminBaseChain(deps.DAL, deps.Issuer, deps.RateLimiter, deps.APIKeyRepo, false)

	wrapCollection := func(h http.HandlerFunc) http.Handler {
		return mw.Chain(h, collectionChain...)
	}

	wrapTenant := func(h http.HandlerFunc) http.Handler {
		return mw.Chain(h, tenantChain...)
	}

	// Collection
	mux.Handle("GET /v2/admin/tenants", wrapCollection(c.ListTenants))
	mux.Handle("POST /v2/admin/tenants", wrapCollection(c.CreateTenant))
	mux.Handle("POST /v2/admin/tenants/test-connection", wrapCollection(c.TestConnection))

	// Item CRUD
	mux.Handle("GET /v2/admin/tenants/{tenant_id}", wrapTenant(c.GetTenant))
	mux.Handle("PUT /v2/admin/tenants/{tenant_id}", wrapTenant(c.UpdateTenant))
	mux.Handle("DELETE /v2/admin/tenants/{tenant_id}", wrapTenant(c.DeleteTenant))

	// Settings
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/settings", wrapTenant(c.GetSettings))
	mux.Handle("PUT /v2/admin/tenants/{tenant_id}/settings", wrapTenant(c.UpdateSettings))

	// Password policy
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/password-policy", wrapTenant(c.GetPasswordPolicy))
	mux.Handle("PUT /v2/admin/tenants/{tenant_id}/password-policy", wrapTenant(c.UpdatePasswordPolicy))

	// Migrations
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/migrate", wrapTenant(c.MigrateTenant))
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/user-store/migrate", wrapTenant(c.MigrateTenant))

	// Schema
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/schema/apply", wrapTenant(c.ApplySchema))

	// Infra
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/infra-stats", wrapTenant(c.InfraStats))
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/cache/test-connection", wrapTenant(c.TestCache))
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/mailing/test", wrapTenant(c.TestMailing))
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/user-store/test-connection", wrapTenant(c.TestTenantDBConnection))

	// Import/Export
	// Literal path /import must be registered before wildcard {tenant_id}/import routes.
	mux.Handle("POST /v2/admin/tenants/import", wrapCollection(c.ImportFromFile))
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/import/validate", wrapTenant(c.ValidateImport))
	mux.Handle("PUT /v2/admin/tenants/{tenant_id}/import", wrapTenant(c.ImportConfig))
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/import", wrapTenant(c.ImportConfig))
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/export", wrapTenant(c.ExportConfig))

	// Push: server-to-server tenant replication (browser never sees secrets)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/push", wrapTenant(c.PushTenant))
}

// sysAdminBaseChain es similar a adminBaseChain pero SIN TenantResolution,
// y forzando SysAdmin (todavía no existe en mw, así que usamos RequireAdmin normal pero sin tenant).
func sysAdminBaseChain(issuer *jwtx.Issuer, limiter mw.RateLimiter, adminCfg mw.AdminConfig, apiKeyRepo repository.APIKeyRepository) []mw.Middleware {
	chain := []mw.Middleware{
		mw.WithRecover(),
		mw.WithRequestID(),
		mw.WithSecurityHeaders(), // MED-6: prevent clickjacking / MIME sniffing
		mw.WithNoStore(),         // MED-6: no cache for sensitive sysadmin responses
	}

	if issuer != nil {
		// Try API key first, then fall through to JWT
		chain = append(chain,
			mw.RequireAdminAuthOrAPIKey(issuer, apiKeyRepo),
		)
		if adminCfg.EnforceAdmin {
			chain = append(chain, mw.RequireAdmin(adminCfg))
		}
	}

	if limiter != nil {
		chain = append(chain, mw.WithRateLimit(mw.RateLimitConfig{
			Limiter: limiter,
			KeyFunc: mw.IPOnlyRateKey,
		}))
	}

	chain = append(chain, mw.WithLogging())

	return chain
}
