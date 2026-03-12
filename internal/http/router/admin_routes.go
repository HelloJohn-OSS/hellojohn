// Package router define las rutas HTTP V2 del servicio.
package router

import (
	"net/http"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	ctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// AdminRouterDeps contiene las dependencias para el router admin.
type AdminRouterDeps struct {
	DAL                    store.DataAccessLayer
	Issuer                 *jwtx.Issuer
	Controllers            *ctrl.Controllers
	RateLimiter            mw.RateLimiter              // Opcional: rate limiter por IP
	MailingTestRateLimiter mw.RateLimiter              // POST /mailing/test: max 5/min por tenant
	AdminConfig            mw.AdminConfig              // Admin enforcement config (from GlobalConfig)
	APIKeyRepo             repository.APIKeyRepository // API key auth (optional, enables X-API-Key header)
}

// RegisterAdminRoutes registra todas las rutas administrativas en un mux.
// Esto se llama desde el server/wiring principal.
func RegisterAdminRoutes(mux *http.ServeMux, deps AdminRouterDeps) {
	dal := deps.DAL
	c := deps.Controllers
	issuer := deps.Issuer
	limiter := deps.RateLimiter
	apiKeyRepo := deps.APIKeyRepo

	// â”€â”€â”€ Admin Auth (PÃºblico - No requiere autenticaciÃ³n) â”€â”€â”€
	mux.Handle("POST /v2/admin/login", adminAuthHandler(limiter, c.Auth.Login))
	mux.Handle("POST /v2/admin/refresh", adminAuthHandler(limiter, c.Auth.Refresh))

	// ─── Admin Invite Accept (Público) ───
	mux.Handle("GET /v2/admin/auth/accept-invite", http.HandlerFunc(c.Admins.ValidateInvite))
	mux.Handle("POST /v2/admin/auth/accept-invite", http.HandlerFunc(c.Admins.AcceptInvite))

	// ─── Admin Management (Solo Global Admin) ───
	adminGlobalMW := func(h http.Handler) http.Handler {
		return mw.Chain(h, mw.RequireAdminAuth(issuer), mw.RequireGlobalAdmin())
	}
	adminGlobalAPIKeyMW := func(h http.Handler) http.Handler {
		return mw.Chain(h, mw.RequireAdminAuthOrAPIKey(issuer, apiKeyRepo), mw.RequireGlobalAdmin())
	}
	mux.Handle("GET /v2/admin/admins", adminGlobalMW(http.HandlerFunc(c.Admins.List)))
	mux.Handle("POST /v2/admin/admins", adminGlobalMW(http.HandlerFunc(c.Admins.Create)))
	mux.Handle("GET /v2/admin/admins/{id}", adminGlobalMW(http.HandlerFunc(c.Admins.Get)))
	mux.Handle("PUT /v2/admin/admins/{id}", adminGlobalMW(http.HandlerFunc(c.Admins.Update)))
	mux.Handle("DELETE /v2/admin/admins/{id}", adminGlobalMW(http.HandlerFunc(c.Admins.Delete)))
	mux.Handle("POST /v2/admin/admins/{id}/disable", adminGlobalMW(http.HandlerFunc(c.Admins.Disable)))
	mux.Handle("POST /v2/admin/admins/{id}/enable", adminGlobalMW(http.HandlerFunc(c.Admins.Enable)))
	mux.Handle("GET /v2/admin/system/email", adminGlobalAPIKeyMW(http.HandlerFunc(c.SystemEmail.Get)))
	mux.Handle("PUT /v2/admin/system/email", adminGlobalAPIKeyMW(http.HandlerFunc(c.SystemEmail.Put)))
	mux.Handle("DELETE /v2/admin/system/email", adminGlobalAPIKeyMW(http.HandlerFunc(c.SystemEmail.Delete)))
	mux.Handle("POST /v2/admin/system/email/test", adminGlobalAPIKeyMW(http.HandlerFunc(c.SystemEmail.Test)))

	// â”€â”€â”€ Admin Tenants (Control Plane - System Admin) â”€â”€â”€
	// NOTA: Estas rutas NO son tenant-scoped porque gestionan la lista de tenants
	RegisterTenantAdminRoutes(mux, deps)

	// â”€â”€â”€ TENANT-SCOPED ROUTES (Enterprise Architecture) â”€â”€â”€
	// TODOS los recursos admin estÃ¡n bajo /tenants/{tenant_id}/
	// Esto previene tenant elevation attacks y hace el modelo explÃ­cito

	// User CRUD (Data Plane - requiere DB)
	// Note: No trailing slash to avoid conflict with tenant routes
	userHandler := adminUserCRUDHandler(dal, issuer, limiter, apiKeyRepo, c.UsersCRUD, true)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/users", userHandler)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/users", userHandler)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/users/{userId}", userHandler)
	mux.Handle("PUT /v2/admin/tenants/{tenant_id}/users/{userId}", userHandler)
	mux.Handle("DELETE /v2/admin/tenants/{tenant_id}/users/{userId}", userHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/users/{userId}/set-password", userHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/users/{userId}/disable", userHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/users/{userId}/enable", userHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/users/{userId}/set-email-verified", userHandler)

	// Bulk User Import/Export (Data Plane - requiere DB)
	importExportHandler := adminImportExportHandler(dal, issuer, limiter, apiKeyRepo, c.Import, c.Export, true)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/users/import", importExportHandler)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/users/import/{job_id}", importExportHandler)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/users/export", importExportHandler)

	// User Invitations (Data Plane - requiere DB)
	invitationHandler := adminInvitationHandler(dal, issuer, limiter, apiKeyRepo, c.Invitation, true)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/invitations", invitationHandler)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/invitations", invitationHandler)
	mux.Handle("DELETE /v2/admin/tenants/{tenant_id}/invitations/{id}", invitationHandler)

	// Token Management (Data Plane - requiere DB)
	tokenHandler := adminTokensHandler(dal, issuer, limiter, apiKeyRepo, c.Tokens, true)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/tokens", tokenHandler)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/tokens/stats", tokenHandler)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/tokens/{tokenId}", tokenHandler)
	mux.Handle("DELETE /v2/admin/tenants/{tenant_id}/tokens/{tokenId}", tokenHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/tokens/revoke-by-user", tokenHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/tokens/revoke-by-client", tokenHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/tokens/revoke-all", tokenHandler)

	// Session Management (Data Plane - requiere DB)
	sessionHandler := adminSessionsHandler(dal, issuer, limiter, apiKeyRepo, c.Sessions, true)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/sessions", sessionHandler)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/sessions/stats", sessionHandler)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/sessions/{sessionId}", sessionHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/sessions/{sessionId}/revoke", sessionHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/sessions/revoke-by-user", sessionHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/sessions/revoke-all", sessionHandler)

	// Clients Management (Control Plane - no requiere DB)
	clientsHandler := adminClientsHandler(dal, issuer, limiter, apiKeyRepo, c.Clients, false)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/clients", clientsHandler)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/clients/{clientId}", clientsHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/clients", clientsHandler)
	mux.Handle("PUT /v2/admin/tenants/{tenant_id}/clients/{clientId}", clientsHandler)
	mux.Handle("DELETE /v2/admin/tenants/{tenant_id}/clients/{clientId}", clientsHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/clients/{clientId}/revoke-secret", clientsHandler)

	// Scopes Management (Control Plane - no requiere DB)
	scopesHandler := adminScopesHandler(dal, issuer, limiter, apiKeyRepo, c.Scopes, false)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/scopes", scopesHandler)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/scopes/{scopeId}", scopesHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/scopes", scopesHandler)
	mux.Handle("PUT /v2/admin/tenants/{tenant_id}/scopes/{scopeId}", scopesHandler)
	mux.Handle("DELETE /v2/admin/tenants/{tenant_id}/scopes/{scopeId}", scopesHandler)

	// Claims Management (Control Plane - no requiere DB)
	claimsHandler := adminClaimsHandler(dal, issuer, limiter, apiKeyRepo, c.Claims, false)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/claims", claimsHandler)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/claims/{claimId}", claimsHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/claims", claimsHandler)
	mux.Handle("PUT /v2/admin/tenants/{tenant_id}/claims/{claimId}", claimsHandler)
	mux.Handle("DELETE /v2/admin/tenants/{tenant_id}/claims/{claimId}", claimsHandler)

	// Consents Management (Data Plane - requiere DB)
	consentsHandler := adminConsentsHandler(dal, issuer, limiter, apiKeyRepo, c.Consents, true)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/consents", consentsHandler)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/consents/{consentId}", consentsHandler)
	mux.Handle("DELETE /v2/admin/tenants/{tenant_id}/consents/{consentId}", consentsHandler)

	// RBAC Management (Data Plane - requiere DB)
	rbacHandler := adminRBACHandler(dal, issuer, limiter, apiKeyRepo, c.RBAC, true)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/rbac/roles", rbacHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/rbac/roles", rbacHandler)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/rbac/roles/{roleId}", rbacHandler)
	mux.Handle("PUT /v2/admin/tenants/{tenant_id}/rbac/roles/{roleId}", rbacHandler)
	mux.Handle("DELETE /v2/admin/tenants/{tenant_id}/rbac/roles/{roleId}", rbacHandler)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/rbac/roles/{roleId}/perms", rbacHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/rbac/roles/{roleId}/perms", rbacHandler)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/rbac/users/{userId}/roles", rbacHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/rbac/users/{userId}/roles", rbacHandler)

	// Webhooks Configuration (Control Plane - no requiere DB)
	webhooksHandler := adminWebhooksHandler(dal, issuer, limiter, apiKeyRepo, c.Webhooks, false)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/webhooks", webhooksHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/webhooks", webhooksHandler)
	mux.Handle("PUT /v2/admin/tenants/{tenant_id}/webhooks/{webhookId}", webhooksHandler)
	mux.Handle("DELETE /v2/admin/tenants/{tenant_id}/webhooks/{webhookId}", webhooksHandler)
	// Webhooks - Delivery History y Test (requieren DB internamente, manejo en controller)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/webhooks/{webhookId}/deliveries", webhooksHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/webhooks/{webhookId}/test", webhooksHandler)

	// Keys Management (Control Plane - no requiere DB)
	keysHandler := adminKeysHandler(dal, issuer, limiter, apiKeyRepo, c.Keys, false)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/keys", keysHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/keys/rotate",
		mw.Chain(http.HandlerFunc(c.Tenants.RotateKeys), adminBaseChain(dal, issuer, limiter, apiKeyRepo, false)...))

	// MFA Status (Control Plane - no requiere DB)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/mfa/status",
		mw.Chain(http.HandlerFunc(c.MFAStatus.GetStatus), adminBaseChain(dal, issuer, limiter, apiKeyRepo, false)...))
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/mfa/config",
		mw.Chain(http.HandlerFunc(c.MFAConfig.GetConfig), adminBaseChain(dal, issuer, limiter, apiKeyRepo, false)...))
	mux.Handle("PUT /v2/admin/tenants/{tenant_id}/mfa/config",
		mw.Chain(http.HandlerFunc(c.MFAConfig.UpdateConfig), adminBaseChain(dal, issuer, limiter, apiKeyRepo, false)...))

	// â”€â”€â”€ Cluster Management (Control Plane - no requiere DB) â”€â”€â”€
	clusterHandler := adminClusterHandler(issuer, limiter, apiKeyRepo, c.Cluster)
	mux.Handle("GET /v2/admin/cluster/nodes", clusterHandler)
	mux.Handle("POST /v2/admin/cluster/nodes", clusterHandler)
	mux.Handle("GET /v2/admin/cluster/stats", clusterHandler)
	mux.Handle("DELETE /v2/admin/cluster/nodes/{id}", clusterHandler)
	// ─── API Keys Management (Control Plane - no requiere DB) ───
	registerAdminAPIKeyRoutes(mux, issuer, limiter, apiKeyRepo, c.APIKey)
	// Audit Logs (Data Plane - requiere DB)
	auditHandler := adminAuditHandler(dal, issuer, limiter, apiKeyRepo, c.Audit, true)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/audit-logs", auditHandler)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/audit-logs/{auditId}", auditHandler)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/audit-logs/purge", auditHandler)

	// GDP Migration (Control Plane - no requiere DB del tenant)
	migrateHandler := mw.Chain(http.HandlerFunc(c.Migrate.MigrateToIsolatedDB), adminBaseChain(dal, issuer, limiter, apiKeyRepo, false)...)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/migrate-to-isolated-db", migrateHandler)

	// ─── Usage Metrics (requiere global DB) ───
	usageTenantChain := adminBaseChain(dal, issuer, limiter, apiKeyRepo, false)
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/usage",
		mw.Chain(http.HandlerFunc(c.Usage.GetTenantUsage), usageTenantChain...))
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/usage/history",
		mw.Chain(http.HandlerFunc(c.Usage.GetHistory), usageTenantChain...))

	usageGlobalChain := adminGlobalChain(issuer, limiter, apiKeyRepo)
	mux.Handle("GET /v2/admin/usage/summary",
		mw.Chain(http.HandlerFunc(c.Usage.GetSummary), usageGlobalChain...))

	// ─── ETL Migration Jobs (requiere global DB) ───
	etlChain := adminBaseChain(dal, issuer, limiter, apiKeyRepo, false)
	mux.Handle("POST /v2/admin/tenants/{tenant_id}/etl-migrate",
		mw.Chain(http.HandlerFunc(c.Etl.StartMigration), etlChain...))
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/etl-migrations",
		mw.Chain(http.HandlerFunc(c.Etl.ListMigrations), etlChain...))
	mux.Handle("GET /v2/admin/tenants/{tenant_id}/etl-migrations/{job_id}",
		mw.Chain(http.HandlerFunc(c.Etl.GetMigration), etlChain...))
}

// â”€â”€â”€ Helpers para crear handlers con middleware chain â”€â”€â”€

func adminBaseChain(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, apiKeyRepo repository.APIKeyRepository, requireDB bool) []mw.Middleware {
	chain := []mw.Middleware{
		mw.WithRecover(),
		mw.WithRequestID(),
		mw.WithSecurityHeaders(), // MED-5: prevent clickjacking / MIME sniffing
		mw.WithNoStore(),         // MED-5: no cache for sensitive admin responses
		// Tenant resolution antes de auth para que estén en context
		mw.WithTenantResolution(dal, false),
		mw.RequireTenant(),
	}

	if requireDB {
		chain = append(chain, mw.RequireTenantDB())
	}

	// Auth obligatorio para admin: accepts JWT Bearer OR X-API-Key
	if issuer != nil {
		chain = append(chain,
			mw.RequireAdminAuthOrAPIKey(issuer, apiKeyRepo),
			// Multi-tenant admin access control
			// Previene tenant elevation attacks (admin de Tenant A accediendo a Tenant B)
			mw.RequireAdminTenantAccess(), // Consume AdminAccessClaims del contexto
		)
	}

	// Rate limiting por IP+Path: cada endpoint admin tiene su propio bucket.
	// IPPathRateKey evita que una rafaga en /tenants queme el cupo de /users, etc.
	if limiter != nil {
		chain = append(chain, mw.WithRateLimit(mw.RateLimitConfig{
			Limiter: limiter,
			KeyFunc: mw.IPPathRateKey,
		}))
	}

	// Logging al final para que tenant/user ya estÃ©n en context
	chain = append(chain, mw.WithLogging())

	return chain
}

// â”€â”€â”€ Admin Clients â”€â”€â”€

func adminClientsHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, apiKeyRepo repository.APIKeyRepository, c *ctrl.ClientsController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/clients"):
			switch r.Method {
			case http.MethodGet:
				c.ListClients(w, r)
			case http.MethodPost:
				c.CreateClient(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/revoke-secret"):
			// Handle /v2/admin/tenants/{tenant_id}/clients/{clientId}/revoke-secret
			if r.Method == http.MethodPost {
				c.RevokeSecret(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		case strings.Contains(path, "/tenants/") && strings.Contains(path, "/clients/"):
			switch r.Method {
			case http.MethodGet:
				c.GetClient(w, r)
			case http.MethodPut, http.MethodPatch:
				c.UpdateClient(w, r)
			case http.MethodDelete:
				c.DeleteClient(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		default:
			httperrors.WriteError(w, httperrors.ErrNotFound)
		}
	})

	chain := adminBaseChain(dal, issuer, limiter, apiKeyRepo, requireDB)
	chain = append(chain, mw.RequireAdminTenantRole("owner"))
	return mw.Chain(handler, chain...)
}

// â”€â”€â”€ Admin Consents â”€â”€â”€

func adminConsentsHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, apiKeyRepo repository.APIKeyRepository, c *ctrl.ConsentsController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/consents"):
			if r.Method == http.MethodGet {
				c.List(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		case strings.Contains(path, "/tenants/") && strings.Contains(path, "/consents/"):
			switch r.Method {
			case http.MethodGet:
				// TODO HIGH-19: Implement GetByConsentID — repository has no GetByID method.
				// Dispatching to List; client must use query params user_id+client_id for single fetch.
				c.List(w, r)
			case http.MethodDelete:
				c.Delete(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		default:
			httperrors.WriteError(w, httperrors.ErrNotFound)
		}
	})

	return mw.Chain(handler, adminBaseChain(dal, issuer, limiter, apiKeyRepo, requireDB)...)
}

// â”€â”€â”€ Admin Users â”€â”€â”€

func adminUsersHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, apiKeyRepo repository.APIKeyRepository, c *ctrl.UsersController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			return
		}

		switch r.URL.Path {
		case "/v2/admin/users/disable":
			c.Disable(w, r)
		case "/v2/admin/users/enable":
			c.Enable(w, r)
		case "/v2/admin/users/resend-verification":
			c.ResendVerification(w, r)
		default:
			httperrors.WriteError(w, httperrors.ErrNotFound)
		}
	})

	return mw.Chain(handler, adminBaseChain(dal, issuer, limiter, apiKeyRepo, requireDB)...)
}

// â”€â”€â”€ Admin Scopes â”€â”€â”€

func adminScopesHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, apiKeyRepo repository.APIKeyRepository, c *ctrl.ScopesController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/scopes"):
			switch r.Method {
			case http.MethodGet:
				c.ListScopes(w, r)
			case http.MethodPost:
				c.UpsertScope(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		case strings.Contains(path, "/tenants/") && strings.Contains(path, "/scopes/"):
			switch r.Method {
			case http.MethodGet:
				c.GetScope(w, r)
			case http.MethodPut:
				c.UpsertScope(w, r)
			case http.MethodDelete:
				c.DeleteScope(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		default:
			httperrors.WriteError(w, httperrors.ErrNotFound)
		}
	})

	chain := adminBaseChain(dal, issuer, limiter, apiKeyRepo, requireDB)
	chain = append(chain, mw.RequireAdminTenantRole("owner"))
	return mw.Chain(handler, chain...)
}

// ─── Admin Claims ───

func adminClaimsHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, apiKeyRepo repository.APIKeyRepository, c *ctrl.ClaimsController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		// GET /v2/admin/tenants/{tenant_id}/claims - Configuración completa
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/claims"):
			if r.Method == http.MethodGet {
				c.GetConfig(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// GET /v2/admin/tenants/{tenant_id}/claims/mappings - Scope-claim mappings
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/claims/mappings"):
			if r.Method == http.MethodGet {
				c.GetScopeMappings(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// GET/PATCH /v2/admin/tenants/{tenant_id}/claims/settings
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/claims/settings"):
			switch r.Method {
			case http.MethodGet:
				c.GetSettings(w, r)
			case http.MethodPatch:
				c.UpdateSettings(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// POST /v2/admin/tenants/{tenant_id}/claims/playground
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/claims/playground"):
			if r.Method == http.MethodPost {
				c.EvaluatePlayground(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// GET/POST /v2/admin/tenants/{tenant_id}/claims/custom
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/claims/custom"):
			switch r.Method {
			case http.MethodGet:
				c.ListCustomClaims(w, r)
			case http.MethodPost:
				c.CreateCustomClaim(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// PATCH /v2/admin/tenants/{tenant_id}/claims/standard/{name}
		case strings.Contains(path, "/tenants/") && strings.Contains(path, "/claims/standard/"):
			if r.Method == http.MethodPatch {
				c.ToggleStandardClaim(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// GET/PUT/DELETE /v2/admin/tenants/{tenant_id}/claims/custom/{id}
		case strings.Contains(path, "/tenants/") && strings.Contains(path, "/claims/custom/"):
			switch r.Method {
			case http.MethodGet:
				c.GetCustomClaim(w, r)
			case http.MethodPut:
				c.UpdateCustomClaim(w, r)
			case http.MethodDelete:
				c.DeleteCustomClaim(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		default:
			httperrors.WriteError(w, httperrors.ErrNotFound)
		}
	})

	chain := adminBaseChain(dal, issuer, limiter, apiKeyRepo, requireDB)
	chain = append(chain, mw.RequireAdminTenantRole("owner"))
	return mw.Chain(handler, chain...)
}

// â”€â”€â”€ Admin RBAC â”€â”€â”€

func adminRBACHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, apiKeyRepo repository.APIKeyRepository, c *ctrl.RBACController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		// /v2/admin/tenants/{tenant_id}/rbac/roles - list or create roles
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/rbac/roles"):
			switch r.Method {
			case http.MethodGet:
				c.ListRoles(w, r)
			case http.MethodPost:
				c.CreateRole(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// /v2/admin/tenants/{tenant_id}/rbac/roles/{roleId}/perms — MUST be before generic /rbac/roles/ case
		case strings.Contains(path, "/rbac/roles/") && strings.HasSuffix(path, "/perms"):
			switch r.Method {
			case http.MethodGet:
				c.GetRolePerms(w, r)
			case http.MethodPost:
				c.UpdateRolePerms(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// /v2/admin/tenants/{tenant_id}/rbac/users/{userId}/roles
		case strings.Contains(path, "/rbac/users/") && strings.HasSuffix(path, "/roles"):
			switch r.Method {
			case http.MethodGet:
				c.GetUserRoles(w, r)
			case http.MethodPost:
				c.UpdateUserRoles(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// /v2/admin/tenants/{tenant_id}/rbac/roles/{roleId}
		case strings.Contains(path, "/tenants/") && strings.Contains(path, "/rbac/roles/"):
			switch r.Method {
			case http.MethodGet:
				c.GetRoleByName(w, r)
			case http.MethodPut:
				c.UpdateRoleByName(w, r)
			case http.MethodDelete:
				c.DeleteRoleByName(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		default:
			httperrors.WriteError(w, httperrors.ErrNotFound)
		}
	})

	chain := adminBaseChain(dal, issuer, limiter, apiKeyRepo, requireDB)
	chain = append(chain, mw.RequireAdminTenantRole("owner"))
	return mw.Chain(handler, chain...)
}

// â”€â”€â”€ Admin User CRUD â”€â”€â”€

func adminUserCRUDHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, apiKeyRepo repository.APIKeyRepository, c *ctrl.UsersCRUDController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		// POST /v2/admin/tenants/{tenant_id}/users/{userId}/disable
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/disable"):
			if r.Method != http.MethodPost {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
				return
			}
			c.DisableUser(w, r)

		// POST /v2/admin/tenants/{tenant_id}/users/{userId}/enable
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/enable"):
			if r.Method != http.MethodPost {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
				return
			}
			c.EnableUser(w, r)

		// POST /v2/admin/tenants/{tenant_id}/users/{userId}/set-email-verified
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/set-email-verified"):
			if r.Method != http.MethodPost {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
				return
			}
			c.SetEmailVerified(w, r)

		// POST /v2/admin/tenants/{tenant_id}/users/{userId}/set-password
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/set-password"):
			if r.Method != http.MethodPost {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
				return
			}
			c.SetPassword(w, r)

		// POST/GET /v2/admin/tenants/{tenant_id}/users - Create user or List users
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/users"):
			if r.Method == http.MethodPost {
				c.CreateUser(w, r)
			} else if r.Method == http.MethodGet {
				c.ListUsers(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// GET/PUT/DELETE /v2/admin/tenants/{tenant_id}/users/{userId}
		case strings.Contains(path, "/tenants/") && strings.Contains(path, "/users/"):
			switch r.Method {
			case http.MethodGet:
				c.GetUser(w, r)
			case http.MethodPut:
				c.UpdateUser(w, r)
			case http.MethodDelete:
				c.DeleteUser(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		default:
			// No match, skip to avoid conflict with other handlers
			http.NotFound(w, r)
		}
	})

	chain := adminBaseChain(dal, issuer, limiter, apiKeyRepo, requireDB)
	chain = append(chain, mw.RequireAdminTenantRole("member"))
	return mw.Chain(handler, chain...)
}

// â”€â”€â”€ Admin Webhooks â”€â”€â”€

// adminImportExportHandler maneja rutas de import/export masivo de usuarios.
func adminImportExportHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, apiKeyRepo repository.APIKeyRepository, importCtrl *ctrl.ImportController, exportCtrl *ctrl.ExportController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		// POST /v2/admin/tenants/{tenant_id}/users/import
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/users/import"):
			if r.Method != http.MethodPost {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
				return
			}
			importCtrl.StartImport(w, r)

		// GET /v2/admin/tenants/{tenant_id}/users/import/{job_id}
		case strings.Contains(path, "/tenants/") && strings.Contains(path, "/users/import/"):
			if r.Method != http.MethodGet {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
				return
			}
			importCtrl.GetImportStatus(w, r)

		// GET /v2/admin/tenants/{tenant_id}/users/export
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/users/export"):
			if r.Method != http.MethodGet {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
				return
			}
			exportCtrl.ExportUsers(w, r)

		default:
			httperrors.WriteError(w, httperrors.ErrNotFound)
		}
	})

	return mw.Chain(handler, adminBaseChain(dal, issuer, limiter, apiKeyRepo, requireDB)...)
}

// adminInvitationHandler maneja rutas de invitaciones de usuario.
func adminInvitationHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, apiKeyRepo repository.APIKeyRepository, c *ctrl.InvitationController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		// POST/GET /v2/admin/tenants/{tenant_id}/invitations
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/invitations"):
			switch r.Method {
			case http.MethodPost:
				c.Create(w, r)
			case http.MethodGet:
				c.List(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// DELETE /v2/admin/tenants/{tenant_id}/invitations/{id}
		case strings.Contains(path, "/tenants/") && strings.Contains(path, "/invitations/"):
			if r.Method == http.MethodDelete {
				c.Revoke(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		default:
			httperrors.WriteError(w, httperrors.ErrNotFound)
		}
	})

	return mw.Chain(handler, adminBaseChain(dal, issuer, limiter, apiKeyRepo, requireDB)...)
}

func adminWebhooksHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, apiKeyRepo repository.APIKeyRepository, c *ctrl.WebhooksController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		// GET/POST /v2/admin/tenants/{tenant_id}/webhooks
		case strings.Contains(path, "/tenants/") && (strings.HasSuffix(path, "/webhooks") || strings.HasSuffix(path, "/webhooks/")):
			switch r.Method {
			case http.MethodGet:
				c.List(w, r)
			case http.MethodPost:
				c.Create(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// GET /v2/admin/tenants/{tenant_id}/webhooks/{webhookId}/deliveries
		case strings.Contains(path, "/webhooks/") && strings.HasSuffix(path, "/deliveries"):
			if r.Method == http.MethodGet {
				c.ListDeliveries(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// POST /v2/admin/tenants/{tenant_id}/webhooks/{webhookId}/test
		case strings.Contains(path, "/webhooks/") && strings.HasSuffix(path, "/test"):
			if r.Method == http.MethodPost {
				c.TestHandshake(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// PUT/DELETE /v2/admin/tenants/{tenant_id}/webhooks/{webhookId}
		case strings.Contains(path, "/tenants/") && strings.Contains(path, "/webhooks/"):
			switch r.Method {
			case http.MethodPut:
				c.Update(w, r)
			case http.MethodDelete:
				c.Delete(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		default:
			httperrors.WriteError(w, httperrors.ErrNotFound)
		}
	})

	chain := adminBaseChain(dal, issuer, limiter, apiKeyRepo, requireDB)
	chain = append(chain, mw.RequireAdminTenantRole("owner"))
	return mw.Chain(handler, chain...)
}

// â”€â”€â”€ Admin Tokens â”€â”€â”€

func adminTokensHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, apiKeyRepo repository.APIKeyRepository, c *ctrl.TokensController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		// GET /v2/admin/tenants/{tenant_id}/tokens/stats
		case strings.Contains(path, "/tokens/stats"):
			if r.Method == http.MethodGet {
				c.GetStats(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// POST /v2/admin/tenants/{tenant_id}/tokens/revoke-by-user
		case strings.Contains(path, "/tokens/revoke-by-user"):
			if r.Method == http.MethodPost {
				c.RevokeByUser(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// POST /v2/admin/tenants/{tenant_id}/tokens/revoke-by-client
		case strings.Contains(path, "/tokens/revoke-by-client"):
			if r.Method == http.MethodPost {
				c.RevokeByClient(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// POST /v2/admin/tenants/{tenant_id}/tokens/revoke-all
		case strings.Contains(path, "/tokens/revoke-all"):
			if r.Method == http.MethodPost {
				c.RevokeAll(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// GET/DELETE /v2/admin/tenants/{tenant_id}/tokens/{tokenId}
		case strings.Contains(path, "/tokens/") && !strings.HasSuffix(path, "/tokens") && !strings.HasSuffix(path, "/tokens/"):
			switch r.Method {
			case http.MethodGet:
				c.Get(w, r)
			case http.MethodDelete:
				c.Revoke(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// GET /v2/admin/tenants/{tenant_id}/tokens
		case strings.HasSuffix(path, "/tokens") || strings.HasSuffix(path, "/tokens/"):
			if r.Method == http.MethodGet {
				c.List(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		default:
			httperrors.WriteError(w, httperrors.ErrNotFound)
		}
	})

	return mw.Chain(handler, adminBaseChain(dal, issuer, limiter, apiKeyRepo, requireDB)...)
}

// â”€â”€â”€ Admin Sessions Handler â”€â”€â”€

func adminSessionsHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, apiKeyRepo repository.APIKeyRepository, c *ctrl.SessionsController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		// GET /v2/admin/tenants/{tenant_id}/sessions/stats
		case strings.Contains(path, "/sessions/stats"):
			if r.Method == http.MethodGet {
				c.GetStats(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// POST /v2/admin/tenants/{tenant_id}/sessions/revoke-by-user
		case strings.Contains(path, "/sessions/revoke-by-user"):
			if r.Method == http.MethodPost {
				c.RevokeUserSessions(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// POST /v2/admin/tenants/{tenant_id}/sessions/revoke-all
		case strings.Contains(path, "/sessions/revoke-all"):
			if r.Method == http.MethodPost {
				c.RevokeAllSessions(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// POST /v2/admin/tenants/{tenant_id}/sessions/{sessionId}/revoke
		case strings.Contains(path, "/revoke") && strings.Contains(path, "/sessions/"):
			if r.Method == http.MethodPost {
				c.RevokeSession(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// GET /v2/admin/tenants/{tenant_id}/sessions/{sessionId}
		case strings.Contains(path, "/sessions/") && !strings.HasSuffix(path, "/sessions") && !strings.HasSuffix(path, "/sessions/"):
			if r.Method == http.MethodGet {
				c.GetSession(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// GET /v2/admin/tenants/{tenant_id}/sessions
		case strings.HasSuffix(path, "/sessions") || strings.HasSuffix(path, "/sessions/"):
			if r.Method == http.MethodGet {
				c.ListSessions(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		default:
			httperrors.WriteError(w, httperrors.ErrNotFound)
		}
	})

	chain := adminBaseChain(dal, issuer, limiter, apiKeyRepo, requireDB)
	chain = append(chain, mw.RequireAdminTenantRole("member"))
	return mw.Chain(handler, chain...)
}

// â”€â”€â”€ Admin Keys â”€â”€â”€

func adminKeysHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, apiKeyRepo repository.APIKeyRepository, c *ctrl.KeysController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/keys"):
			// GET /v2/admin/tenants/{tenant_id}/keys
			if r.Method == http.MethodGet {
				c.ListKeys(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/keys/rotate"):
			// POST /v2/admin/tenants/{tenant_id}/keys/rotate
			if r.Method == http.MethodPost {
				c.RotateKeys(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		default:
			httperrors.WriteError(w, httperrors.ErrNotFound)
		}
	})

	chain := adminBaseChain(dal, issuer, limiter, apiKeyRepo, requireDB)
	chain = append(chain, mw.RequireAdminTenantRole("owner"))
	return mw.Chain(handler, chain...)
}

// adminClusterHandler crea un handler para endpoints de cluster management.
// No requiere tenant context â€” las rutas de cluster son globales (no tenant-scoped).
func adminClusterHandler(issuer *jwtx.Issuer, limiter mw.RateLimiter, apiKeyRepo repository.APIKeyRepository, c *ctrl.ClusterController) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		method := r.Method

		switch {
		case path == "/v2/admin/cluster/nodes" || path == "/v2/admin/cluster/nodes/":
			// GET /v2/admin/cluster/nodes - List nodes
			// POST /v2/admin/cluster/nodes - Add node
			if method == http.MethodGet {
				c.GetNodes(w, r)
			} else if method == http.MethodPost {
				c.AddNode(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		case path == "/v2/admin/cluster/stats" || path == "/v2/admin/cluster/stats/":
			// GET /v2/admin/cluster/stats - Get stats
			if method == http.MethodGet {
				c.GetStats(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		case strings.HasPrefix(path, "/v2/admin/cluster/nodes/"):
			// DELETE /v2/admin/cluster/nodes/{id} - Remove node
			if method == http.MethodDelete {
				c.RemoveNode(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		default:
			httperrors.WriteError(w, httperrors.ErrNotFound)
		}
	})

	return mw.Chain(handler, adminGlobalChain(issuer, limiter, apiKeyRepo)...)
}

// registerAdminAPIKeyRoutes registra cada sub-ruta de API Keys con su propio handler
// para que net/http ServeMux establezca r.PathValue("id") nativamente.
func registerAdminAPIKeyRoutes(mux *http.ServeMux, issuer *jwtx.Issuer, limiter mw.RateLimiter, apiKeyRepo repository.APIKeyRepository, c *ctrl.APIKeyController) {
	chain := adminGlobalChain(issuer, limiter, apiKeyRepo)
	mux.Handle("POST /v2/admin/api-keys", mw.Chain(http.HandlerFunc(c.Create), chain...))
	mux.Handle("GET /v2/admin/api-keys", mw.Chain(http.HandlerFunc(c.List), chain...))
	mux.Handle("GET /v2/admin/api-keys/{id}", mw.Chain(http.HandlerFunc(c.Get), chain...))
	mux.Handle("DELETE /v2/admin/api-keys/{id}", mw.Chain(http.HandlerFunc(c.Revoke), chain...))
	mux.Handle("POST /v2/admin/api-keys/{id}/rotate", mw.Chain(http.HandlerFunc(c.Rotate), chain...))
}

// adminGlobalChain crea un middleware chain para endpoints de admin que NO son tenant-scoped
// (ej: cluster management). Tiene auth de admin pero sin tenant resolution.
func adminGlobalChain(issuer *jwtx.Issuer, limiter mw.RateLimiter, apiKeyRepo repository.APIKeyRepository) []mw.Middleware {
	chain := []mw.Middleware{
		mw.WithRecover(),
		mw.WithRequestID(),
		mw.WithSecurityHeaders(),
		mw.WithNoStore(),
	}

	if issuer != nil {
		chain = append(chain,
			mw.RequireAdminAuthOrAPIKey(issuer, apiKeyRepo),
			mw.RequireGlobalAdmin(),
		)
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

// adminAuthHandler crea un handler para endpoints de autenticaciÃ³n de admin (pÃºblicos).
// Solo aplica recover, request ID, security headers, rate limit, y logging.
// NO aplica auth ni tenant resolution.
func adminAuthHandler(limiter mw.RateLimiter, handlerFunc http.HandlerFunc) http.Handler {
	chain := []mw.Middleware{
		mw.WithRecover(),
		mw.WithRequestID(),
		mw.WithSecurityHeaders(),
		mw.WithNoStore(),
	}

	if limiter != nil {
		chain = append(chain, mw.WithRateLimit(mw.RateLimitConfig{
			Limiter: limiter,
			KeyFunc: mw.IPPathRateKey,
		}))
	}

	chain = append(chain, mw.WithLogging())

	return mw.Chain(handlerFunc, chain...)
}

// â”€â”€â”€ Admin Audit Logs â”€â”€â”€

func adminAuditHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, apiKeyRepo repository.APIKeyRepository, c *ctrl.AuditController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case strings.HasSuffix(path, "/audit-logs/purge"):
			if r.Method == http.MethodPost {
				c.Purge(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		case strings.HasSuffix(path, "/audit-logs"):
			if r.Method == http.MethodGet {
				c.List(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		case strings.Contains(path, "/audit-logs/"):
			if r.Method == http.MethodGet {
				c.Get(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		default:
			httperrors.WriteError(w, httperrors.ErrNotFound)
		}
	})

	return mw.Chain(handler, adminBaseChain(dal, issuer, limiter, apiKeyRepo, requireDB)...)
}
