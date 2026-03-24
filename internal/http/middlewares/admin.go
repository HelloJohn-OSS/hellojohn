package middlewares

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/claims"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/http/errors"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// =================================================================================
// ADMIN MIDDLEWARES
// =================================================================================

// AdminConfig configura el comportamiento de los middlewares de admin.
type AdminConfig struct {
	// EnforceAdmin si es true, requiere que el usuario sea admin.
	// Si es false (modo desarrollo), siempre permite.
	EnforceAdmin bool
	// AdminSubs lista de user IDs que son admin por defecto (fallback de emergencia)
	AdminSubs []string
}

// RequireAdmin valida que el usuario tenga permisos de admin.
// Reglas (en este orden):
//  1. Si ADMIN_ENFORCE != "1": permitir (modo compatible por defecto).
//  2. Si custom.is_admin == true => permitir.
//  3. Si custom.roles incluye "admin" => permitir.
//  4. Si el sub (user id) está en ADMIN_SUBS (lista CSV) => permitir.
//     Si no, 403.
func RequireAdmin(cfg AdminConfig) Middleware {
	adminSubs := make(map[string]struct{})
	for _, s := range cfg.AdminSubs {
		adminSubs[s] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.EnforceAdmin {
				next.ServeHTTP(w, r)
				return
			}

			cl := GetClaims(r.Context())
			if cl == nil {
				errors.WriteError(w, errors.ErrUnauthorized.WithDetail("no claims in context"))
				return
			}

			// 1. is_admin global en map root
			if v, ok := cl["is_admin"].(bool); ok && v {
				next.ServeHTTP(w, r)
				return
			}
			// 2. roles: ["admin", ...] en root
			if arr := ClaimStringSlice(cl, "roles"); len(arr) > 0 {
				for _, role := range arr {
					if strings.EqualFold(role, "admin") {
						next.ServeHTTP(w, r)
						return
					}
				}
			}

			// Admin por SUB (fallback por env)
			if sub := ClaimString(cl, "sub"); sub != "" {
				if _, ok := adminSubs[sub]; ok {
					next.ServeHTTP(w, r)
					return
				}
			}

			errors.WriteError(w, errors.ErrForbidden.WithDetail("admin required"))
		})
	}
}

// RequireSysAdmin valida admin del SISTEMA usando el namespace anclado al issuer.
// Reglas:
//  1. Si ADMIN_ENFORCE != "1": permitir (modo dev/compat).
//  2. Leer custom[SYS_NS].is_admin == true => permitir.
//  3. Leer custom[SYS_NS].roles incluye "sys:admin" => permitir.
//  4. Fallback de emergencia: sub ∈ ADMIN_SUBS => permitir.
func RequireSysAdmin(issuer *jwtx.Issuer, cfg AdminConfig) Middleware {
	adminSubs := make(map[string]struct{})
	for _, s := range cfg.AdminSubs {
		adminSubs[s] = struct{}{}
	}
	sysNS := claims.SystemNamespace(issuer.Iss)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !cfg.EnforceAdmin {
				next.ServeHTTP(w, r)
				return
			}

			cl := GetClaims(r.Context())
			if cl == nil {
				errors.WriteError(w, errors.ErrUnauthorized.WithDetail("no claims in context"))
				return
			}

			// System Namespace Claims in Root
			if sysMap := ClaimMap(cl, sysNS); sysMap != nil {
				if v, ok := sysMap["is_admin"].(bool); ok && v {
					next.ServeHTTP(w, r)
					return
				}
				if rs := ClaimStringSlice(sysMap, "roles"); len(rs) > 0 {
					for _, role := range rs {
						if strings.EqualFold(role, "sys:admin") {
							next.ServeHTTP(w, r)
							return
						}
					}
				}
			}

			// Fallback ADMIN_SUBS
			if sub := ClaimString(cl, "sub"); sub != "" {
				if _, ok := adminSubs[sub]; ok {
					next.ServeHTTP(w, r)
					return
				}
			}

			errors.WriteError(w, errors.ErrForbidden.WithDetail("sys admin required"))
		})
	}
}

// =================================================================================
// ADMIN JWT MIDDLEWARES (V2)
// =================================================================================

// RequireAdminAuth valida que el token JWT es un admin access token válido.
// Este middleware debe usarse en rutas de administración que requieren autenticación admin.
func RequireAdminAuth(issuer *jwtx.Issuer) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extraer token del header Authorization
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				errors.WriteError(w, errors.ErrUnauthorized.WithDetail("authorization header required"))
				return
			}

			// Validar formato "Bearer <token>"
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				errors.WriteError(w, errors.ErrUnauthorized.WithDetail("invalid authorization header format"))
				return
			}

			token := parts[1]

			// Verificar token admin
			adminClaims, err := issuer.VerifyAdminAccess(r.Context(), token)
			if err != nil {
				errors.WriteError(w, errors.ErrUnauthorized.WithDetail("invalid admin token"))
				return
			}

			// Guardar claims en contexto
			ctx := SetAdminClaims(r.Context(), adminClaims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireAdminAuthOrAPIKey validates admin auth using EITHER:
//   - X-API-Key header → validates via API key repo, creates synthetic AdminAccessClaims
//   - Authorization: Bearer <JWT> → validates via JWT issuer (existing flow)
//
// This allows hjctl/MCP and other API key-based clients to access admin routes
// alongside the existing JWT-based admin panel.
func RequireAdminAuthOrAPIKey(issuer *jwtx.Issuer, apiKeyRepo repository.APIKeyRepository) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try API key first if X-API-Key header is present
			raw := strings.TrimSpace(r.Header.Get("X-API-Key"))
			if raw != "" && apiKeyRepo != nil {
				if !strings.HasPrefix(raw, "hj_") || len(raw) < 20 {
					errors.WriteError(w, errors.ErrUnauthorized.WithDetail("invalid API key format"))
					return
				}

				hash := hashAPIKey(raw)

				key, err := apiKeyRepo.GetByHash(r.Context(), hash)
				if err != nil || !key.IsActive() {
					errors.WriteError(w, errors.ErrUnauthorized.WithDetail("invalid or expired API key"))
					return
				}

				// Scope-based access control. Structured as a switch so every scope is reachable
				// (previously a blanket reject made the readonly branch dead code — AK-5).
				switch key.Scope {
				case repository.APIKeyScopeAdmin:
					// Full admin access — no additional restrictions.

				case repository.APIKeyScopeCloud:
					// Cloud keys cannot access sensitive management paths.
					for _, blocked := range repository.CloudScopeBlockedPaths {
						if strings.HasPrefix(r.URL.Path, blocked) {
							errors.WriteError(w, errors.ErrForbidden.WithDetail("cloud key cannot access this path"))
							return
						}
					}
					// AK-1: Block JWT signing key management endpoints (M-BACK-4: prefix-based).
					// These are dynamic paths like /v2/admin/tenants/{id}/keys and
					// /v2/admin/tenants/{id}/keys/rotate which cannot be listed as
					// simple prefixes in CloudScopeBlockedPaths.
					if idx := strings.Index(r.URL.Path, "/keys"); idx != -1 {
						// Verify it's actually a /keys path segment (not e.g. /api-keys).
						suffix := r.URL.Path[idx:]
						if suffix == "/keys" || strings.HasPrefix(suffix, "/keys/") {
							errors.WriteError(w, errors.ErrForbidden.WithDetail("cloud scope cannot access key management endpoints"))
							return
						}
					}

				case repository.APIKeyScopeReadOnly:
					// Readonly keys: GET and HEAD only.
					if r.Method != http.MethodGet && r.Method != http.MethodHead {
						errors.WriteError(w, errors.ErrForbidden.WithDetail("readonly key cannot mutate"))
						return
					}

				default:
					// C-BACK-2: tenant:{slug} scoped keys: ONLY allowed on /v2/admin/tenants/{slug}/* paths.
					slug := key.TenantID()
					if slug == "" {
						errors.WriteError(w, errors.ErrForbidden.WithDetail("API key scope insufficient for admin access"))
						return
					}
					allowedPrefix := "/v2/admin/tenants/" + slug + "/"
					// Also allow the exact tenant root path (no trailing slash variant)
					tenantRootPath := "/v2/admin/tenants/" + slug
					if !strings.HasPrefix(r.URL.Path, allowedPrefix) && r.URL.Path != tenantRootPath {
						errors.WriteError(w, errors.ErrForbidden.WithDetail("API key scope insufficient for this endpoint"))
						return
					}
				}

				// Build synthetic AdminAccessClaims from API key
				adminType := "global"
				var tenants []jwtx.TenantAccessClaim
				if slug := key.TenantID(); slug != "" {
					adminType = "tenant"
					tenants = []jwtx.TenantAccessClaim{{ID: slug, Role: "owner"}}
				} else {
					// Global admin/cloud keys: grant wildcard tenant access so that
					// filterTenantsByAdminClaims returns all tenants instead of [].
					tenants = []jwtx.TenantAccessClaim{{ID: "*", Role: "owner"}}
				}

				syntheticClaims := &jwtx.AdminAccessClaims{
					AdminID:   "apikey:" + key.ID,
					Email:     "apikey+" + key.ID + "@system.local",
					AdminType: adminType,
					Tenants:   tenants,
					Perms:     jwtx.DefaultAdminPerms(adminType),
				}

				// Track API key usage (best-effort, non-blocking)
				go func(keyID string) {
					updateCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					_ = apiKeyRepo.UpdateLastUsed(updateCtx, keyID, time.Now())
				}(key.ID)

				// Inject API key + admin claims into context
				ctx := SetAdminClaims(r.Context(), syntheticClaims)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Fallback: JWT admin auth (existing flow)
			RequireAdminAuth(issuer)(next).ServeHTTP(w, r)
		})
	}
}

// RequireAdminTenantAccess valida que el admin tenga acceso al tenant solicitado.
// Este middleware debe usarse DESPUÉS de RequireAdminAuth.
//
// - Admins tipo "global" tienen acceso a todos los tenants
// - Admins tipo "tenant" solo tienen acceso a sus assigned_tenants
//
// El tenant_id se puede obtener de:
// - Query param: ?tenant_id=acme
// - Path param: /v2/admin/tenants/{tenant_id}/...
// - Request body (JSON): {"tenant_id": "acme"}
func RequireAdminTenantAccess() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			adminClaims := GetAdminClaims(r.Context())
			if adminClaims == nil {
				errors.WriteError(w, errors.ErrUnauthorized.WithDetail("admin claims not found"))
				return
			}

			// Admins globales tienen acceso a todo
			if strings.EqualFold(strings.TrimSpace(adminClaims.AdminType), "global") {
				next.ServeHTTP(w, r)
				return
			}

			// Priorizar tenant canónico del contexto para evitar ambigüedad slug/id.
			// Con WithTenantResolution + RequireTenant, el contexto ya contiene el tenant resuelto.
			requestedTenantRef := strings.TrimSpace(extractTenantID(r))
			ctxTenant := GetTenant(r.Context())
			canonicalTenantID := ""
			canonicalTenantSlug := ""
			if ctxTenant != nil {
				canonicalTenantID = strings.TrimSpace(ctxTenant.ID())
				canonicalTenantSlug = strings.TrimSpace(ctxTenant.Slug())
			}

			candidateRefs := make([]string, 0, 3)
			if canonicalTenantID != "" {
				candidateRefs = append(candidateRefs, canonicalTenantID)
			}
			if canonicalTenantSlug != "" && !strings.EqualFold(canonicalTenantSlug, canonicalTenantID) {
				candidateRefs = append(candidateRefs, canonicalTenantSlug)
			}
			// Fallback de compatibilidad para rutas sin tenant en contexto.
			if len(candidateRefs) == 0 && requestedTenantRef != "" {
				candidateRefs = append(candidateRefs, requestedTenantRef)
			}

			if len(candidateRefs) == 0 {
				// Only global admins may access routes without a tenant ref.
				// Tenant-scoped admins must always have a valid tenant context.
				// Note: global admin check already returned early above, so reaching
				// here means the admin is tenant-scoped but has no tenant ref.
				errors.WriteError(w, errors.ErrForbidden.WithDetail("tenant context required"))
				return
			}

			hasAccess := hasTenantAccess(adminClaims.Tenants, candidateRefs...)
			logTenant := canonicalTenantID
			if logTenant == "" {
				logTenant = requestedTenantRef
			}

			if !hasAccess {
				logger.From(r.Context()).With(
					logger.Layer("middleware"),
					logger.Component("admin.authz"),
					logger.Op("RequireAdminTenantAccess"),
					logger.String("admin_id", adminClaims.AdminID),
					logger.String("admin_type", adminClaims.AdminType),
					logger.String("requested_tenant", logTenant),
				).Warn("admin tenant access denied",
					logger.String("reason", "tenant_elevation_attempt"),
					logger.Path(r.URL.Path),
					logger.Method(r.Method),
					logger.Int("allowed_tenants_count", len(adminClaims.Tenants)),
				)
				errors.WriteError(w, errors.ErrForbidden.WithDetail("admin does not have access to this tenant"))
				return
			}

			logger.From(r.Context()).With(
				logger.Layer("middleware"),
				logger.Component("admin.authz"),
				logger.Op("RequireAdminTenantAccess"),
				logger.String("admin_id", adminClaims.AdminID),
				logger.String("admin_type", adminClaims.AdminType),
				logger.String("tenant", logTenant),
			).Debug("admin tenant access granted",
				logger.Path(r.URL.Path),
				logger.Method(r.Method),
			)

			next.ServeHTTP(w, r)
		})
	}
}

func hasTenantAccess(allowedTenants []jwtx.TenantAccessClaim, refs ...string) bool {
	if len(allowedTenants) == 0 || len(refs) == 0 {
		return false
	}

	allowed := make(map[string]struct{}, len(allowedTenants))
	for _, entry := range allowedTenants {
		if n := normalizeTenantRef(entry.ID); n != "" {
			allowed[n] = struct{}{}
		}
	}

	for _, ref := range refs {
		n := normalizeTenantRef(ref)
		if n == "" {
			continue
		}
		if _, ok := allowed[n]; ok {
			return true
		}
	}

	return false
}

// roleHierarchy define el orden de permisos de los roles de admin de tenant.
var roleHierarchy = map[string]int{
	"readonly": 1,
	"member":   2,
	"owner":    3,
}

// RequireAdminTenantRole valida que el admin tenga el rol mínimo requerido en el tenant.
// Debe usarse DESPUÉS de RequireAdminAuth y RequireAdminTenantAccess.
// Los admins globales siempre pasan.
func RequireAdminTenantRole(minRole string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			adminClaims := GetAdminClaims(r.Context())
			if adminClaims == nil {
				errors.WriteError(w, errors.ErrUnauthorized.WithDetail("admin claims not found"))
				return
			}

			// Admins globales siempre pasan
			if strings.EqualFold(strings.TrimSpace(adminClaims.AdminType), "global") {
				next.ServeHTTP(w, r)
				return
			}

			// Obtener tenant del contexto
			ctxTenant := GetTenant(r.Context())
			tenantSlug := ""
			if ctxTenant != nil {
				tenantSlug = ctxTenant.Slug()
			}
			if tenantSlug == "" {
				tenantSlug = strings.TrimSpace(extractTenantID(r))
			}
			if tenantSlug == "" {
				errors.WriteError(w, errors.ErrForbidden.WithDetail("tenant context required for role check"))
				return
			}

			// Buscar rol del admin para este tenant
			actualRole := ""
			for _, entry := range adminClaims.Tenants {
				if strings.EqualFold(normalizeTenantRef(entry.ID), normalizeTenantRef(tenantSlug)) {
					actualRole = entry.Role
					break
				}
			}

			if actualRole == "" {
				errors.WriteError(w, errors.ErrForbidden.WithDetail("admin has no role for this tenant"))
				return
			}

			minLevel := roleHierarchy[strings.ToLower(minRole)]
			actualLevel := roleHierarchy[strings.ToLower(actualRole)]

			if actualLevel < minLevel {
				errors.WriteError(w, errors.ErrForbidden.WithDetail(
					fmt.Sprintf("role %q required, admin has %q", minRole, actualRole),
				))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func normalizeTenantRef(ref string) string {
	return strings.ToLower(strings.TrimSpace(ref))
}

// extractTenantID intenta extraer el tenant_id de varios lugares de la request.
// ESTANDARIZADO (FASE 2): Prioriza path parameter "tenant_id" de rutas /v2/admin/tenants/{tenant_id}/...
func extractTenantID(r *http.Request) string {
	// 1. Path param: /v2/admin/tenants/{tenant_id}/... (MÉTODO ESTÁNDAR - FASE 2)
	if tid := strings.TrimSpace(r.PathValue("tenant_id")); tid != "" {
		return tid
	}

	// 2. Query param: ?tenant_id=acme (fallback legacy)
	if tid := r.URL.Query().Get("tenant_id"); tid != "" {
		return tid
	}

	// 3. Query param alternativo: ?tenant=acme (fallback legacy)
	if tid := r.URL.Query().Get("tenant"); tid != "" {
		return tid
	}

	// TODO: Parse JSON body si es POST/PUT/PATCH
	// Por ahora, solo soportamos path params y query params

	return ""
}

// RequireGlobalAdmin valida que el admin autenticado sea de tipo "global".
// Debe usarse DESPUÉS de RequireAdminAuth.
func RequireGlobalAdmin() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetAdminClaims(r.Context())
			if claims == nil {
				errors.WriteError(w, errors.ErrUnauthorized.WithDetail("admin claims required"))
				return
			}
			if !strings.EqualFold(strings.TrimSpace(claims.AdminType), "global") {
				errors.WriteError(w, errors.ErrForbidden.WithDetail("global admin required"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
