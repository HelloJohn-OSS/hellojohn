// Package router define las rutas HTTP V2 del servicio.
package router

import (
	"net/http"
	"strings"

	ctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// AdminRouterDeps contiene las dependencias para el router admin.
type AdminRouterDeps struct {
	DAL         store.DataAccessLayer
	Issuer      *jwtx.Issuer
	Controllers *ctrl.Controllers
	RateLimiter mw.RateLimiter // Opcional: rate limiter por IP
}

// RegisterAdminRoutes registra todas las rutas administrativas en un mux.
// Esto se llama desde el server/wiring principal.
func RegisterAdminRoutes(mux *http.ServeMux, deps AdminRouterDeps) {
	dal := deps.DAL
	c := deps.Controllers
	issuer := deps.Issuer
	limiter := deps.RateLimiter

	// ─── Admin Auth (Público - No requiere autenticación) ───
	mux.Handle("POST /v2/admin/login", adminAuthHandler(limiter, c.Auth.Login))
	mux.Handle("POST /v2/admin/refresh", adminAuthHandler(limiter, c.Auth.Refresh))

	// ─── Admin Routes (Requieren autenticación) ───

	// Admin Clients (Control Plane - no requiere DB)
	mux.Handle("/v2/admin/clients", adminClientsHandler(dal, issuer, limiter, c.Clients, false))
	mux.Handle("/v2/admin/clients/", adminClientsHandler(dal, issuer, limiter, c.Clients, false))

	// Admin Consents (Data Plane - requiere DB)
	mux.Handle("/v2/admin/consents", adminConsentsHandler(dal, issuer, limiter, c.Consents, true))
	mux.Handle("/v2/admin/consents/", adminConsentsHandler(dal, issuer, limiter, c.Consents, true))

	// Admin Users (Data Plane - requiere DB)
	mux.Handle("/v2/admin/users/", adminUsersHandler(dal, issuer, limiter, c.Users, true))

	// Admin Scopes (Control Plane - no requiere DB)
	mux.Handle("/v2/admin/scopes", adminScopesHandler(dal, issuer, limiter, c.Scopes, false))
	mux.Handle("/v2/admin/scopes/", adminScopesHandler(dal, issuer, limiter, c.Scopes, false))

	// Admin Claims (Control Plane - no requiere DB)
	mux.Handle("/v2/admin/claims", adminClaimsHandler(dal, issuer, limiter, c.Claims, false))
	mux.Handle("/v2/admin/claims/", adminClaimsHandler(dal, issuer, limiter, c.Claims, false))

	// Admin RBAC (Data Plane - requiere DB)
	mux.Handle("/v2/admin/rbac/", adminRBACHandler(dal, issuer, limiter, c.RBAC, true))

	// Admin Keys (Control Plane - no requiere DB)
	mux.Handle("/v2/admin/keys", adminKeysHandler(dal, issuer, limiter, c.Keys, false))
	mux.Handle("/v2/admin/keys/", adminKeysHandler(dal, issuer, limiter, c.Keys, false))

	// Admin Cluster (Control Plane - no requiere DB)
	mux.Handle("/v2/admin/cluster/", adminClusterHandler(dal, issuer, limiter, c.Cluster, false))

	// Admin Tenants (Control Plane - System Admin)
	RegisterTenantAdminRoutes(mux, deps)

	// User CRUD (Data Plane - requiere DB)
	// Note: No trailing slash to avoid conflict with tenant routes
	userHandler := adminUserCRUDHandler(dal, issuer, limiter, c.UsersCRUD, true)
	mux.Handle("POST /v2/admin/tenants/{id}/users", userHandler)
	mux.Handle("GET /v2/admin/tenants/{id}/users", userHandler)
	mux.Handle("GET /v2/admin/tenants/{id}/users/{userId}", userHandler)
	mux.Handle("PUT /v2/admin/tenants/{id}/users/{userId}", userHandler)
	mux.Handle("DELETE /v2/admin/tenants/{id}/users/{userId}", userHandler)

	// Token Management (Data Plane - requiere DB)
	tokenHandler := adminTokensHandler(dal, issuer, limiter, c.Tokens, true)
	mux.Handle("GET /v2/admin/tenants/{id}/tokens", tokenHandler)
	mux.Handle("GET /v2/admin/tenants/{id}/tokens/stats", tokenHandler)
	mux.Handle("GET /v2/admin/tenants/{id}/tokens/{tokenId}", tokenHandler)
	mux.Handle("DELETE /v2/admin/tenants/{id}/tokens/{tokenId}", tokenHandler)
	mux.Handle("POST /v2/admin/tenants/{id}/tokens/revoke-by-user", tokenHandler)
	mux.Handle("POST /v2/admin/tenants/{id}/tokens/revoke-by-client", tokenHandler)
	mux.Handle("POST /v2/admin/tenants/{id}/tokens/revoke-all", tokenHandler)

	// Session Management (Data Plane - requiere DB)
	sessionHandler := adminSessionsHandler(dal, issuer, limiter, c.Sessions, true)
	mux.Handle("GET /v2/admin/tenants/{id}/sessions", sessionHandler)
	mux.Handle("GET /v2/admin/tenants/{id}/sessions/stats", sessionHandler)
	mux.Handle("GET /v2/admin/tenants/{id}/sessions/{sessionId}", sessionHandler)
	mux.Handle("POST /v2/admin/tenants/{id}/sessions/{sessionId}/revoke", sessionHandler)
	mux.Handle("POST /v2/admin/tenants/{id}/sessions/revoke-by-user", sessionHandler)
	mux.Handle("POST /v2/admin/tenants/{id}/sessions/revoke-all", sessionHandler)
}

// ─── Helpers para crear handlers con middleware chain ───

func adminBaseChain(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, requireDB bool) []mw.Middleware {
	chain := []mw.Middleware{
		mw.WithRecover(),
		mw.WithRequestID(),
		// Tenant resolution antes de auth para que estén en context
		mw.WithTenantResolution(dal, false),
		mw.RequireTenant(),
	}

	if requireDB {
		chain = append(chain, mw.RequireTenantDB())
	}

	// Auth obligatorio para admin
	if issuer != nil {
		chain = append(chain,
			mw.RequireAuth(issuer),
			mw.RequireAdmin(mw.AdminConfigFromEnv()),
		)
	}

	// Rate limiting por IP (sin client_id ya que admin panel no lo tiene)
	if limiter != nil {
		chain = append(chain, mw.WithRateLimit(mw.RateLimitConfig{
			Limiter: limiter,
			KeyFunc: mw.IPOnlyRateKey,
		}))
	}

	// Logging al final para que tenant/user ya estén en context
	chain = append(chain, mw.WithLogging())

	return chain
}

// ─── Admin Clients ───

func adminClientsHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, c *ctrl.ClientsController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case path == "/v2/admin/clients" || path == "/v2/admin/clients/":
			switch r.Method {
			case http.MethodGet:
				c.ListClients(w, r)
			case http.MethodPost:
				c.CreateClient(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		case strings.HasSuffix(path, "/revoke"):
			// Handle /v2/admin/clients/{clientId}/revoke
			if r.Method == http.MethodPost {
				c.RevokeSecret(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		case strings.HasPrefix(path, "/v2/admin/clients/"):
			switch r.Method {
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

	return mw.Chain(handler, adminBaseChain(dal, issuer, limiter, requireDB)...)
}

// ─── Admin Consents ───

func adminConsentsHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, c *ctrl.ConsentsController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case r.Method == http.MethodPost && path == "/v2/admin/consents/upsert":
			c.Upsert(w, r)

		case r.Method == http.MethodPost && path == "/v2/admin/consents/revoke":
			c.Revoke(w, r)

		case r.Method == http.MethodGet && strings.HasPrefix(path, "/v2/admin/consents/by-user/"):
			c.ListByUser(w, r)

		case r.Method == http.MethodGet && (path == "/v2/admin/consents" || path == "/v2/admin/consents/"):
			c.List(w, r)

		case r.Method == http.MethodDelete && strings.HasPrefix(path, "/v2/admin/consents/"):
			c.Delete(w, r)

		default:
			httperrors.WriteError(w, httperrors.ErrNotFound)
		}
	})

	return mw.Chain(handler, adminBaseChain(dal, issuer, limiter, requireDB)...)
}

// ─── Admin Users ───

func adminUsersHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, c *ctrl.UsersController, requireDB bool) http.Handler {
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

	return mw.Chain(handler, adminBaseChain(dal, issuer, limiter, requireDB)...)
}

// ─── Admin Scopes ───

func adminScopesHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, c *ctrl.ScopesController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case path == "/v2/admin/scopes" || path == "/v2/admin/scopes/":
			switch r.Method {
			case http.MethodGet:
				c.ListScopes(w, r)
			case http.MethodPost, http.MethodPut:
				c.UpsertScope(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		case strings.HasPrefix(path, "/v2/admin/scopes/"):
			switch r.Method {
			case http.MethodDelete:
				c.DeleteScope(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		default:
			httperrors.WriteError(w, httperrors.ErrNotFound)
		}
	})

	return mw.Chain(handler, adminBaseChain(dal, issuer, limiter, requireDB)...)
}

// ─── Admin Claims ───

func adminClaimsHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, c *ctrl.ClaimsController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		// GET /v2/admin/claims - Configuración completa
		case path == "/v2/admin/claims" || path == "/v2/admin/claims/":
			if r.Method == http.MethodGet {
				c.GetConfig(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// GET /v2/admin/claims/mappings - Scope-claim mappings
		case path == "/v2/admin/claims/mappings":
			if r.Method == http.MethodGet {
				c.GetScopeMappings(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// GET/PATCH /v2/admin/claims/settings
		case path == "/v2/admin/claims/settings":
			switch r.Method {
			case http.MethodGet:
				c.GetSettings(w, r)
			case http.MethodPatch:
				c.UpdateSettings(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// GET/POST /v2/admin/claims/custom
		case path == "/v2/admin/claims/custom" || path == "/v2/admin/claims/custom/":
			switch r.Method {
			case http.MethodGet:
				c.ListCustomClaims(w, r)
			case http.MethodPost:
				c.CreateCustomClaim(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// PATCH /v2/admin/claims/standard/{name}
		case strings.HasPrefix(path, "/v2/admin/claims/standard/"):
			if r.Method == http.MethodPatch {
				c.ToggleStandardClaim(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// GET/PUT/DELETE /v2/admin/claims/custom/{id}
		case strings.HasPrefix(path, "/v2/admin/claims/custom/"):
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

	return mw.Chain(handler, adminBaseChain(dal, issuer, limiter, requireDB)...)
}

// ─── Admin RBAC ───

func adminRBACHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, c *ctrl.RBACController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		// /v2/admin/rbac/permissions - list available permissions
		case path == "/v2/admin/rbac/permissions" || path == "/v2/admin/rbac/permissions/":
			if r.Method == http.MethodGet {
				c.ListPermissions(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// /v2/admin/rbac/users/{userID}/roles
		case strings.Contains(path, "/users/") && strings.HasSuffix(path, "/roles"):
			switch r.Method {
			case http.MethodGet:
				c.GetUserRoles(w, r)
			case http.MethodPost:
				c.UpdateUserRoles(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// /v2/admin/rbac/roles/{role}/perms - per-role permissions (legacy endpoints)
		case strings.Contains(path, "/roles/") && strings.HasSuffix(path, "/perms"):
			switch r.Method {
			case http.MethodGet:
				c.GetRolePerms(w, r)
			case http.MethodPost:
				c.UpdateRolePerms(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// /v2/admin/rbac/roles - list or create roles
		case path == "/v2/admin/rbac/roles" || path == "/v2/admin/rbac/roles/":
			switch r.Method {
			case http.MethodGet:
				c.ListRoles(w, r)
			case http.MethodPost:
				c.CreateRole(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// /v2/admin/rbac/roles/{name} - get, update, delete specific role
		case strings.HasPrefix(path, "/v2/admin/rbac/roles/"):
			switch r.Method {
			case http.MethodGet:
				c.GetRoleByName(w, r)
			case http.MethodPut, http.MethodPatch:
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

	return mw.Chain(handler, adminBaseChain(dal, issuer, limiter, requireDB)...)
}

// ─── Admin User CRUD ───

func adminUserCRUDHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, c *ctrl.UsersCRUDController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		// POST /v2/admin/tenants/{id}/users/{userId}/disable
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/disable"):
			if r.Method != http.MethodPost {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
				return
			}
			c.DisableUser(w, r)

		// POST /v2/admin/tenants/{id}/users/{userId}/enable
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/enable"):
			if r.Method != http.MethodPost {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
				return
			}
			c.EnableUser(w, r)

		// POST /v2/admin/tenants/{id}/users/{userId}/set-email-verified
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/set-email-verified"):
			if r.Method != http.MethodPost {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
				return
			}
			c.SetEmailVerified(w, r)

		// POST /v2/admin/tenants/{id}/users/{userId}/set-password
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/set-password"):
			if r.Method != http.MethodPost {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
				return
			}
			c.SetPassword(w, r)

		// POST/GET /v2/admin/tenants/{id}/users - Create user or List users
		case strings.Contains(path, "/tenants/") && strings.HasSuffix(path, "/users"):
			if r.Method == http.MethodPost {
				c.CreateUser(w, r)
			} else if r.Method == http.MethodGet {
				c.ListUsers(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// GET/PUT/DELETE /v2/admin/tenants/{id}/users/{userId}
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

	return mw.Chain(handler, adminBaseChain(dal, issuer, limiter, requireDB)...)
}

// ─── Admin Tokens ───

func adminTokensHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, c *ctrl.TokensController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		// GET /v2/admin/tenants/{id}/tokens/stats
		case strings.Contains(path, "/tokens/stats"):
			if r.Method == http.MethodGet {
				c.GetStats(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// POST /v2/admin/tenants/{id}/tokens/revoke-by-user
		case strings.Contains(path, "/tokens/revoke-by-user"):
			if r.Method == http.MethodPost {
				c.RevokeByUser(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// POST /v2/admin/tenants/{id}/tokens/revoke-by-client
		case strings.Contains(path, "/tokens/revoke-by-client"):
			if r.Method == http.MethodPost {
				c.RevokeByClient(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// POST /v2/admin/tenants/{id}/tokens/revoke-all
		case strings.Contains(path, "/tokens/revoke-all"):
			if r.Method == http.MethodPost {
				c.RevokeAll(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// GET/DELETE /v2/admin/tenants/{id}/tokens/{tokenId}
		case strings.Contains(path, "/tokens/") && !strings.HasSuffix(path, "/tokens") && !strings.HasSuffix(path, "/tokens/"):
			switch r.Method {
			case http.MethodGet:
				c.Get(w, r)
			case http.MethodDelete:
				c.Revoke(w, r)
			default:
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// GET /v2/admin/tenants/{id}/tokens
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

	return mw.Chain(handler, adminBaseChain(dal, issuer, limiter, requireDB)...)
}

// ─── Admin Sessions Handler ───

func adminSessionsHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, c *ctrl.SessionsController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		// GET /v2/admin/tenants/{id}/sessions/stats
		case strings.Contains(path, "/sessions/stats"):
			if r.Method == http.MethodGet {
				c.GetStats(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// POST /v2/admin/tenants/{id}/sessions/revoke-by-user
		case strings.Contains(path, "/sessions/revoke-by-user"):
			if r.Method == http.MethodPost {
				c.RevokeUserSessions(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// POST /v2/admin/tenants/{id}/sessions/revoke-all
		case strings.Contains(path, "/sessions/revoke-all"):
			if r.Method == http.MethodPost {
				c.RevokeAllSessions(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// POST /v2/admin/tenants/{id}/sessions/{sessionId}/revoke
		case strings.Contains(path, "/revoke") && strings.Contains(path, "/sessions/"):
			if r.Method == http.MethodPost {
				c.RevokeSession(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// GET /v2/admin/tenants/{id}/sessions/{sessionId}
		case strings.Contains(path, "/sessions/") && !strings.HasSuffix(path, "/sessions") && !strings.HasSuffix(path, "/sessions/"):
			if r.Method == http.MethodGet {
				c.GetSession(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		// GET /v2/admin/tenants/{id}/sessions
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

	return mw.Chain(handler, adminBaseChain(dal, issuer, limiter, requireDB)...)
}

// ─── Admin Keys ───

func adminKeysHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, c *ctrl.KeysController, requireDB bool) http.Handler {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case path == "/v2/admin/keys" || path == "/v2/admin/keys/":
			// GET /v2/admin/keys?tenant_id=...
			if r.Method == http.MethodGet {
				c.ListKeys(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		case path == "/v2/admin/keys/rotate":
			// POST /v2/admin/keys/rotate
			if r.Method == http.MethodPost {
				c.RotateKeys(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		case strings.HasSuffix(path, "/revoke") && r.Method == http.MethodPost:
			// POST /v2/admin/keys/{kid}/revoke
			c.RevokeKey(w, r)

		case strings.HasPrefix(path, "/v2/admin/keys/"):
			// GET /v2/admin/keys/{kid}
			if r.Method == http.MethodGet {
				c.GetKey(w, r)
			} else {
				httperrors.WriteError(w, httperrors.ErrMethodNotAllowed)
			}

		default:
			httperrors.WriteError(w, httperrors.ErrNotFound)
		}
	})

	return mw.Chain(handler, adminBaseChain(dal, issuer, limiter, requireDB)...)
}

// adminClusterHandler crea un handler para endpoints de cluster management.
func adminClusterHandler(dal store.DataAccessLayer, issuer *jwtx.Issuer, limiter mw.RateLimiter, c *ctrl.ClusterController, requireDB bool) http.Handler {
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

	return mw.Chain(handler, adminBaseChain(dal, issuer, limiter, requireDB)...)
}

// adminAuthHandler crea un handler para endpoints de autenticación de admin (públicos).
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
