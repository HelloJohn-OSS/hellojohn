package jwt

import "strings"

// TenantAccessClaim representa el acceso de un admin a un tenant con rol.
// Se serializa como {"tenant_id":"550e8400-...","role":"owner"} en el JWT.
type TenantAccessClaim struct {
	ID   string `json:"tenant_id"` // UUID del tenant
	Role string `json:"role"`      // "owner" | "member" | "readonly"
}

// AdminAccessClaims son los claims del access token de admin
type AdminAccessClaims struct {
	AdminID   string              `json:"sub"`
	Email     string              `json:"email"`
	AdminType string              `json:"admin_type"` // "global" | "tenant"
	Tenants   []TenantAccessClaim `json:"tenants,omitempty"`
	Perms     []string            `json:"perms,omitempty"` // permisos administrativos (ej: audit:read, audit:purge)
}

// AdminRefreshClaims son los claims del refresh token de admin
type AdminRefreshClaims struct {
	AdminID string `json:"sub"`
	Type    string `json:"type"` // "admin_refresh"
}

// DefaultAdminPerms retorna el set mínimo de permisos administrativos por tipo.
func DefaultAdminPerms(adminType string) []string {
	switch strings.ToLower(strings.TrimSpace(adminType)) {
	case "global":
		return []string{
			"audit:read",
			"audit:purge",
		}
	case "tenant":
		return []string{
			"audit:read",
		}
	default:
		return nil
	}
}
