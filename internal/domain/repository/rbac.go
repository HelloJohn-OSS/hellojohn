package repository

import (
	"context"
	"time"
)

// Role representa un rol definido en el sistema.
type Role struct {
	ID           string
	TenantID     string
	Name         string
	Description  string
	Permissions  []string
	InheritsFrom *string
	System       bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// RoleInput representa los datos para crear/actualizar un rol.
type RoleInput struct {
	Name         string
	Description  string
	InheritsFrom *string
}

// RBACRepository define operaciones sobre roles y permisos.
// Esta interfaz es opcional: no todos los drivers la implementan.
type RBACRepository interface {
	// GetUserRoles retorna los roles asignados a un usuario.
	// Ejemplo: ["sys:admin", "billing:manager"]
	GetUserRoles(ctx context.Context, userID string) ([]string, error)

	// GetUserPermissions retorna los permisos efectivos de un usuario.
	// Derivados de sus roles. Ejemplo: ["users:read", "users:write"]
	GetUserPermissions(ctx context.Context, userID string) ([]string, error)

	// AssignRole asigna un rol a un usuario.
	AssignRole(ctx context.Context, tenantID, userID, role string) error

	// RemoveRole quita un rol de un usuario.
	RemoveRole(ctx context.Context, tenantID, userID, role string) error

	// ─── Role Permissions (opcional) ───

	// GetRolePermissions retorna los permisos de un rol.
	GetRolePermissions(ctx context.Context, tenantID, role string) ([]string, error)

	// AddPermissionToRole añade un permiso a un rol.
	AddPermissionToRole(ctx context.Context, tenantID, role, permission string) error

	// RemovePermissionFromRole quita un permiso de un rol.
	RemovePermissionFromRole(ctx context.Context, tenantID, role, permission string) error

	// ─── CRUD de Roles ───

	// ListRoles lista todos los roles de un tenant.
	ListRoles(ctx context.Context, tenantID string) ([]Role, error)

	// GetRole obtiene un rol por nombre.
	GetRole(ctx context.Context, tenantID, name string) (*Role, error)

	// CreateRole crea un nuevo rol.
	CreateRole(ctx context.Context, tenantID string, input RoleInput) (*Role, error)

	// UpdateRole actualiza un rol existente.
	UpdateRole(ctx context.Context, tenantID, name string, input RoleInput) (*Role, error)

	// DeleteRole elimina un rol. No permite eliminar roles sistema.
	DeleteRole(ctx context.Context, tenantID, name string) error

	// GetRoleUsersCount retorna cuántos usuarios tienen asignado un rol.
	GetRoleUsersCount(ctx context.Context, tenantID, role string) (int, error)
}
