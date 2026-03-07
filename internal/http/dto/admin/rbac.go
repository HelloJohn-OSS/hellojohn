// Package admin contiene DTOs para endpoints administrativos.
package admin

// RBACRolesUpdateRequest representa la entrada para actualizar roles de usuario.
type RBACRolesUpdateRequest struct {
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
}

// RBACUserRolesResponse representa los roles de un usuario.
type RBACUserRolesResponse struct {
	UserID string   `json:"user_id"`
	Roles  []string `json:"roles"`
}

// RBACPermsUpdateRequest representa la entrada para actualizar permisos de un rol.
type RBACPermsUpdateRequest struct {
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
}

// RBACRolePermsResponse representa los permisos de un rol.
type RBACRolePermsResponse struct {
	TenantID string   `json:"tenant_id"`
	Role     string   `json:"role"`
	Perms    []string `json:"perms"`
}

// ─── Role CRUD DTOs ───

// RoleResponse representa un rol en la respuesta.
type RoleResponse struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Description  string   `json:"description,omitempty"`
	InheritsFrom *string  `json:"inherits_from,omitempty"`
	System       bool     `json:"system"`
	Permissions  []string `json:"permissions"`
	UsersCount   int      `json:"users_count"`
	CreatedAt    string   `json:"created_at"`
	UpdatedAt    string   `json:"updated_at"`
}

// CreateRoleRequest representa la entrada para crear un rol.
type CreateRoleRequest struct {
	Name         string   `json:"name"`
	Description  string   `json:"description,omitempty"`
	InheritsFrom *string  `json:"inherits_from,omitempty"`
	Permissions  []string `json:"permissions,omitempty"`
}

// UpdateRoleRequest representa la entrada para actualizar un rol.
type UpdateRoleRequest struct {
	Description  *string  `json:"description,omitempty"`
	InheritsFrom *string  `json:"inherits_from,omitempty"`
	Permissions  []string `json:"permissions,omitempty"`
}

// PermissionInfo representa información sobre un permiso disponible.
type PermissionInfo struct {
	Name        string `json:"name"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
}
