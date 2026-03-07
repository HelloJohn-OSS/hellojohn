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
	chain := sysAdminBaseChain(deps.Issuer, deps.RateLimiter, deps.AdminConfig, deps.APIKeyRepo)

	wrap := func(h http.HandlerFunc) http.Handler {
		return mw.Chain(h, chain...)
	}

	// ─── Collection ───
	mux.Handle("GET /v2/admin/tenants", wrap(c.ListTenants))
	mux.Handle("POST /v2/admin/tenants", wrap(c.CreateTenant))
	mux.Handle("POST /v2/admin/tenants/test-connection", wrap(c.TestConnection))

	// ─── Item CRUD ───
	// tenant_id puede ser slug o UUID — DAL resuelve ambos
	mux.Handle("GET /v2/admin/tenants/{tenant_id}", wrap(c.GetTenant))
	mux.Handle("PUT /v2/admin/tenants/{tenant_id}", wrap(c.UpdateTenant))
	mux.Handle("DELETE /v2/admin/tenants/{tenant_id}", wrap(c.DeleteTenant))

	// ─── Settings ───
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/settings", wrap(c.GetSettings))
	mux.Handle("PUT /v2/admin/tenants/{tenant_id}/settings", wrap(c.UpdateSettings))

	// ─── Password Policy ───
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/password-policy", wrap(c.GetPasswordPolicy))
	mux.Handle("PUT /v2/admin/tenants/{tenant_id}/password-policy", wrap(c.UpdatePasswordPolicy))

	// ─── Migrations ───
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/migrate", wrap(c.MigrateTenant))
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/user-store/migrate", wrap(c.MigrateTenant))

	// ─── Schema ───
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/schema/apply", wrap(c.ApplySchema))

	// ─── Infra ───
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/infra-stats", wrap(c.InfraStats))
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/cache/test-connection", wrap(c.TestCache))
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/mailing/test", wrap(c.TestMailing))
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/user-store/test-connection", wrap(c.TestTenantDBConnection))

	// ─── Import/Export ───
	// Literal path /import must be registered before wildcard {tenant_id}/import routes.
	mux.Handle("POST /v2/admin/tenants/import", wrap(c.ImportFromFile))
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/import/validate", wrap(c.ValidateImport))
	mux.Handle("PUT /v2/admin/tenants/{tenant_id}/import", wrap(c.ImportConfig))
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/import", wrap(c.ImportConfig))
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/export", wrap(c.ExportConfig))

	// Push: server-to-server tenant replication (browser never sees secrets)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/push", wrap(c.PushTenant))
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
