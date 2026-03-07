package admin

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// RBACService define las operaciones RBAC para el admin API.
type RBACService interface {
	GetUserRoles(ctx context.Context, tda store.TenantDataAccess, userID string) ([]string, error)
	UpdateUserRoles(ctx context.Context, tda store.TenantDataAccess, userID string, add, remove []string) ([]string, error)
	GetRolePerms(ctx context.Context, tda store.TenantDataAccess, role string) ([]string, error)
	UpdateRolePerms(ctx context.Context, tda store.TenantDataAccess, role string, add, remove []string) ([]string, error)

	// CRUD de Roles
	ListRoles(ctx context.Context, tda store.TenantDataAccess) ([]dto.RoleResponse, error)
	GetRole(ctx context.Context, tda store.TenantDataAccess, name string) (*dto.RoleResponse, error)
	CreateRole(ctx context.Context, tda store.TenantDataAccess, req dto.CreateRoleRequest) (*dto.RoleResponse, error)
	UpdateRole(ctx context.Context, tda store.TenantDataAccess, name string, req dto.UpdateRoleRequest) (*dto.RoleResponse, error)
	DeleteRole(ctx context.Context, tda store.TenantDataAccess, name string) error
	ListPermissions(ctx context.Context) []dto.PermissionInfo
}

// RBACReader es la interfaz para leer roles RBAC.
type RBACReader interface {
	GetUserRoles(ctx context.Context, userID string) ([]string, error)
}

// RBACWriter es la interfaz para escribir roles/permisos RBAC.
type RBACWriter interface {
	AssignUserRoles(ctx context.Context, userID string, add []string) error
	RemoveUserRoles(ctx context.Context, userID string, remove []string) error
	GetRolePerms(ctx context.Context, tenantID, role string) ([]string, error)
	AddRolePerms(ctx context.Context, tenantID, role string, add []string) error
	RemoveRolePerms(ctx context.Context, tenantID, role string, remove []string) error
}

// rbacService implementa RBACService.
type rbacService struct {
	auditBus *audit.AuditBus
}

// NewRBACService crea un nuevo servicio RBAC.
func NewRBACService(auditBus *audit.AuditBus) RBACService {
	return &rbacService{auditBus: auditBus}
}

const componentRBAC = "admin.rbac"

var (
	ErrRBACNotSupported = fmt.Errorf("RBAC not supported by store")
)

func (s *rbacService) GetUserRoles(ctx context.Context, tda store.TenantDataAccess, userID string) ([]string, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentRBAC),
		logger.Op("GetUserRoles"),
		logger.UserID(userID),
	)

	if err := tda.RequireDB(); err != nil {
		return nil, err
	}

	// Intentar obtener RBACReader del TDA
	reader, ok := tda.(RBACReader)
	if !ok {
		log.Warn("store does not support RBAC read")
		return nil, ErrRBACNotSupported
	}

	roles, err := reader.GetUserRoles(ctx, userID)
	if err != nil {
		log.Error("failed to get user roles", logger.Err(err))
		return nil, err
	}

	return roles, nil
}

func (s *rbacService) UpdateUserRoles(ctx context.Context, tda store.TenantDataAccess, userID string, add, remove []string) ([]string, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentRBAC),
		logger.Op("UpdateUserRoles"),
		logger.UserID(userID),
	)

	if err := tda.RequireDB(); err != nil {
		return nil, err
	}

	// Intentar obtener RBACWriter del TDA
	writer, ok := tda.(RBACWriter)
	if !ok {
		log.Warn("store does not support RBAC write")
		return nil, ErrRBACNotSupported
	}

	// Normalizar y deduplicar
	add = dedupTrim(add)
	remove = dedupTrim(remove)

	if len(add) > 0 {
		if err := writer.AssignUserRoles(ctx, userID, add); err != nil {
			emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventRoleAssigned, userID, audit.TargetUser, audit.ResultError, map[string]any{
				"reason": "assign_roles_failed",
			})
			log.Error("failed to assign roles", logger.Err(err))
			return nil, err
		}
		for _, role := range add {
			emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventRoleAssigned, userID, audit.TargetUser, audit.ResultSuccess, map[string]any{
				"role": role,
			})
		}
	}

	if len(remove) > 0 {
		if err := writer.RemoveUserRoles(ctx, userID, remove); err != nil {
			emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventRoleRemoved, userID, audit.TargetUser, audit.ResultError, map[string]any{
				"reason": "remove_roles_failed",
			})
			log.Error("failed to remove roles", logger.Err(err))
			return nil, err
		}
		for _, role := range remove {
			emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventRoleRemoved, userID, audit.TargetUser, audit.ResultSuccess, map[string]any{
				"role": role,
			})
		}
	}

	// Re-leer estado final
	reader, ok := tda.(RBACReader)
	if !ok {
		return nil, ErrRBACNotSupported
	}

	return reader.GetUserRoles(ctx, userID)
}

func (s *rbacService) GetRolePerms(ctx context.Context, tda store.TenantDataAccess, role string) ([]string, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentRBAC),
		logger.Op("GetRolePerms"),
		logger.String("role", role),
	)

	if err := tda.RequireDB(); err != nil {
		return nil, err
	}

	writer, ok := tda.(RBACWriter)
	if !ok {
		log.Warn("store does not support RBAC write")
		return nil, ErrRBACNotSupported
	}

	perms, err := writer.GetRolePerms(ctx, tda.ID(), role)
	if err != nil {
		log.Error("failed to get role perms", logger.Err(err))
		return nil, err
	}

	return perms, nil
}

func (s *rbacService) UpdateRolePerms(ctx context.Context, tda store.TenantDataAccess, role string, add, remove []string) ([]string, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentRBAC),
		logger.Op("UpdateRolePerms"),
		logger.String("role", role),
	)

	if err := tda.RequireDB(); err != nil {
		return nil, err
	}

	writer, ok := tda.(RBACWriter)
	if !ok {
		log.Warn("store does not support RBAC write")
		return nil, ErrRBACNotSupported
	}

	// Normalizar y deduplicar
	add = dedupTrim(add)
	remove = dedupTrim(remove)

	tenantID := tda.ID()

	if len(add) > 0 {
		if err := writer.AddRolePerms(ctx, tenantID, role, add); err != nil {
			emitAdminEvent(ctx, s.auditBus, tenantID, audit.EventRoleUpdated, role, audit.TargetRole, audit.ResultError, map[string]any{
				"reason": "add_permissions_failed",
				"role":   role,
			})
			log.Error("failed to add perms", logger.Err(err))
			return nil, err
		}
	}

	if len(remove) > 0 {
		if err := writer.RemoveRolePerms(ctx, tenantID, role, remove); err != nil {
			emitAdminEvent(ctx, s.auditBus, tenantID, audit.EventRoleUpdated, role, audit.TargetRole, audit.ResultError, map[string]any{
				"reason": "remove_permissions_failed",
				"role":   role,
			})
			log.Error("failed to remove perms", logger.Err(err))
			return nil, err
		}
	}

	if len(add) > 0 || len(remove) > 0 {
		emitAdminEvent(ctx, s.auditBus, tenantID, audit.EventRoleUpdated, role, audit.TargetRole, audit.ResultSuccess, map[string]any{
			"role": role,
		})
	}

	// Re-leer estado final
	return writer.GetRolePerms(ctx, tenantID, role)
}

// dedupTrim aplica trim, elimina vacíos y deduplica.
func dedupTrim(in []string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// ─── CRUD de Roles ───

var roleNameRegex = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

var (
	ErrInvalidRoleName        = fmt.Errorf("invalid role name: must be lowercase alphanumeric with hyphens")
	ErrRoleNameTooLong        = fmt.Errorf("role name too long: max 100 characters")
	ErrCannotDeleteSystemRole = fmt.Errorf("cannot delete system role")
)

func (s *rbacService) ListRoles(ctx context.Context, tda store.TenantDataAccess) ([]dto.RoleResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentRBAC),
		logger.Op("ListRoles"),
	)

	if err := tda.RequireDB(); err != nil {
		return nil, err
	}

	roles, err := tda.RBAC().ListRoles(ctx, tda.ID())
	if err != nil {
		log.Error("failed to list roles", logger.Err(err))
		return nil, err
	}

	result := make([]dto.RoleResponse, 0, len(roles))
	for _, role := range roles {
		perms, permErr := tda.RBAC().GetRolePermissions(ctx, tda.ID(), role.Name)
		if permErr != nil {
			log.Warn("failed to get permissions for role", logger.String("role", role.Name), logger.Err(permErr))
		}
		usersCount, countErr := tda.RBAC().GetRoleUsersCount(ctx, tda.ID(), role.Name)
		if countErr != nil {
			log.Warn("failed to get user count for role", logger.String("role", role.Name), logger.Err(countErr))
		}

		result = append(result, toRoleResponse(role, perms, usersCount))
	}

	return result, nil
}

func (s *rbacService) GetRole(ctx context.Context, tda store.TenantDataAccess, name string) (*dto.RoleResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentRBAC),
		logger.Op("GetRole"),
		logger.String("role", name),
	)

	if err := tda.RequireDB(); err != nil {
		return nil, err
	}

	role, err := tda.RBAC().GetRole(ctx, tda.ID(), name)
	if err != nil {
		log.Error("failed to get role", logger.Err(err))
		return nil, err
	}

	perms, permErr := tda.RBAC().GetRolePermissions(ctx, tda.ID(), name)
	if permErr != nil {
		log.Warn("failed to get permissions for role", logger.Err(permErr))
	}
	usersCount, countErr := tda.RBAC().GetRoleUsersCount(ctx, tda.ID(), name)
	if countErr != nil {
		log.Warn("failed to get user count for role", logger.Err(countErr))
	}

	resp := toRoleResponse(*role, perms, usersCount)
	return &resp, nil
}

func (s *rbacService) CreateRole(ctx context.Context, tda store.TenantDataAccess, req dto.CreateRoleRequest) (*dto.RoleResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentRBAC),
		logger.Op("CreateRole"),
		logger.String("role", req.Name),
	)

	if err := tda.RequireDB(); err != nil {
		return nil, err
	}

	// Validar nombre
	if err := validateRoleName(req.Name); err != nil {
		return nil, err
	}

	// Validar herencia si se especifica
	if req.InheritsFrom != nil && *req.InheritsFrom != "" {
		_, err := tda.RBAC().GetRole(ctx, tda.ID(), *req.InheritsFrom)
		if err != nil {
			return nil, fmt.Errorf("parent role not found: %s", *req.InheritsFrom)
		}
	}

	input := repository.RoleInput{
		Name:         req.Name,
		Description:  req.Description,
		InheritsFrom: req.InheritsFrom,
	}

	role, err := tda.RBAC().CreateRole(ctx, tda.ID(), input)
	if err != nil {
		emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventRoleCreated, req.Name, audit.TargetRole, audit.ResultError, map[string]any{
			"reason": "create_role_failed",
			"role":   req.Name,
		})
		log.Error("failed to create role", logger.Err(err))
		return nil, err
	}

	// Asignar permisos si se especifican
	if len(req.Permissions) > 0 {
		for _, perm := range req.Permissions {
			if err := tda.RBAC().AddPermissionToRole(ctx, tda.ID(), role.Name, perm); err != nil {
				emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventRoleCreated, role.Name, audit.TargetRole, audit.ResultError, map[string]any{
					"reason":     "assign_permission_failed",
					"role":       role.Name,
					"permission": perm,
				})
				log.Error("failed to assign permission to role", logger.Err(err), logger.String("permission", perm))
				return nil, err
			}
		}
	}

	perms, err := tda.RBAC().GetRolePermissions(ctx, tda.ID(), role.Name)
	if err != nil {
		emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventRoleCreated, role.Name, audit.TargetRole, audit.ResultError, map[string]any{
			"reason": "load_permissions_failed",
			"role":   role.Name,
		})
		log.Error("failed to load role permissions", logger.Err(err))
		return nil, err
	}
	emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventRoleCreated, role.Name, audit.TargetRole, audit.ResultSuccess, map[string]any{
		"role": role.Name,
	})
	resp := toRoleResponse(*role, perms, 0)
	return &resp, nil
}

func (s *rbacService) UpdateRole(ctx context.Context, tda store.TenantDataAccess, name string, req dto.UpdateRoleRequest) (*dto.RoleResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentRBAC),
		logger.Op("UpdateRole"),
		logger.String("role", name),
	)

	if err := tda.RequireDB(); err != nil {
		return nil, err
	}

	// Verificar que existe
	existingRole, err := tda.RBAC().GetRole(ctx, tda.ID(), name)
	if err != nil {
		return nil, err
	}

	if existingRole.System {
		// Solo permitir actualizar permisos en roles sistema
		if req.Description != nil || req.InheritsFrom != nil {
			return nil, fmt.Errorf("cannot modify system role properties")
		}
	}

	input := repository.RoleInput{
		Name: name,
	}
	if req.Description != nil {
		input.Description = *req.Description
	} else {
		input.Description = existingRole.Description
	}
	input.InheritsFrom = req.InheritsFrom

	role, err := tda.RBAC().UpdateRole(ctx, tda.ID(), name, input)
	if err != nil {
		emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventRoleUpdated, name, audit.TargetRole, audit.ResultError, map[string]any{
			"reason": "update_role_failed",
			"role":   name,
		})
		log.Error("failed to update role", logger.Err(err))
		return nil, err
	}

	// Actualizar permisos si se especifican
	if req.Permissions != nil {
		// Obtener permisos actuales
		currentPerms, err := tda.RBAC().GetRolePermissions(ctx, tda.ID(), name)
		if err != nil {
			emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventRoleUpdated, name, audit.TargetRole, audit.ResultError, map[string]any{
				"reason": "load_current_permissions_failed",
				"role":   name,
			})
			log.Error("failed to load current role permissions", logger.Err(err))
			return nil, err
		}
		currentSet := make(map[string]struct{})
		for _, p := range currentPerms {
			currentSet[p] = struct{}{}
		}

		newSet := make(map[string]struct{})
		for _, p := range req.Permissions {
			newSet[p] = struct{}{}
		}

		// Agregar nuevos
		for _, p := range req.Permissions {
			if _, exists := currentSet[p]; !exists {
				if err := tda.RBAC().AddPermissionToRole(ctx, tda.ID(), name, p); err != nil {
					emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventRoleUpdated, name, audit.TargetRole, audit.ResultError, map[string]any{
						"reason":     "add_permission_failed",
						"role":       name,
						"permission": p,
					})
					log.Error("failed to add permission to role", logger.Err(err), logger.String("permission", p))
					return nil, err
				}
			}
		}

		// Remover los que ya no están
		for _, p := range currentPerms {
			if _, exists := newSet[p]; !exists {
				if err := tda.RBAC().RemovePermissionFromRole(ctx, tda.ID(), name, p); err != nil {
					emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventRoleUpdated, name, audit.TargetRole, audit.ResultError, map[string]any{
						"reason":     "remove_permission_failed",
						"role":       name,
						"permission": p,
					})
					log.Error("failed to remove permission from role", logger.Err(err), logger.String("permission", p))
					return nil, err
				}
			}
		}
	}

	perms, err := tda.RBAC().GetRolePermissions(ctx, tda.ID(), name)
	if err != nil {
		emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventRoleUpdated, name, audit.TargetRole, audit.ResultError, map[string]any{
			"reason": "load_permissions_failed",
			"role":   name,
		})
		log.Error("failed to load role permissions", logger.Err(err))
		return nil, err
	}
	usersCount, err := tda.RBAC().GetRoleUsersCount(ctx, tda.ID(), name)
	if err != nil {
		emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventRoleUpdated, name, audit.TargetRole, audit.ResultError, map[string]any{
			"reason": "load_role_users_count_failed",
			"role":   name,
		})
		log.Error("failed to load role users count", logger.Err(err))
		return nil, err
	}

	resp := toRoleResponse(*role, perms, usersCount)
	emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventRoleUpdated, name, audit.TargetRole, audit.ResultSuccess, map[string]any{
		"role": name,
	})
	return &resp, nil
}

func (s *rbacService) DeleteRole(ctx context.Context, tda store.TenantDataAccess, name string) error {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentRBAC),
		logger.Op("DeleteRole"),
		logger.String("role", name),
	)

	if err := tda.RequireDB(); err != nil {
		return err
	}

	// El repository ya valida que no sea sistema
	if err := tda.RBAC().DeleteRole(ctx, tda.ID(), name); err != nil {
		emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventRoleDeleted, name, audit.TargetRole, audit.ResultError, map[string]any{
			"reason": "delete_role_failed",
			"role":   name,
		})
		log.Error("failed to delete role", logger.Err(err))
		return err
	}

	emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventRoleDeleted, name, audit.TargetRole, audit.ResultSuccess, map[string]any{
		"role": name,
	})

	log.Info("role deleted")
	return nil
}

func (s *rbacService) ListPermissions(ctx context.Context) []dto.PermissionInfo {
	return StandardPermissions
}

// StandardPermissions define los permisos estándar del sistema.
var StandardPermissions = []dto.PermissionInfo{
	// Users
	{Name: "users:read", Resource: "users", Action: "read", Description: "Ver usuarios"},
	{Name: "users:write", Resource: "users", Action: "write", Description: "Crear/editar usuarios"},
	{Name: "users:delete", Resource: "users", Action: "delete", Description: "Eliminar usuarios"},

	// Roles
	{Name: "roles:read", Resource: "roles", Action: "read", Description: "Ver roles"},
	{Name: "roles:write", Resource: "roles", Action: "write", Description: "Gestionar roles"},
	{Name: "roles:delete", Resource: "roles", Action: "delete", Description: "Eliminar roles"},

	// Profile
	{Name: "profile:read", Resource: "profile", Action: "read", Description: "Ver propio perfil"},
	{Name: "profile:write", Resource: "profile", Action: "write", Description: "Editar propio perfil"},

	// Clients
	{Name: "clients:read", Resource: "clients", Action: "read", Description: "Ver aplicaciones"},
	{Name: "clients:write", Resource: "clients", Action: "write", Description: "Gestionar aplicaciones"},
	{Name: "clients:delete", Resource: "clients", Action: "delete", Description: "Eliminar aplicaciones"},

	// Sessions
	{Name: "sessions:read", Resource: "sessions", Action: "read", Description: "Ver sesiones"},
	{Name: "sessions:revoke", Resource: "sessions", Action: "revoke", Description: "Revocar sesiones"},

	// Settings
	{Name: "settings:read", Resource: "settings", Action: "read", Description: "Ver configuración"},
	{Name: "settings:write", Resource: "settings", Action: "write", Description: "Modificar configuración"},

	// Audit
	{Name: "audit:read", Resource: "audit", Action: "read", Description: "Ver logs de auditoría"},

	// Reports
	{Name: "reports:read", Resource: "reports", Action: "read", Description: "Ver reportes"},
	{Name: "reports:export", Resource: "reports", Action: "export", Description: "Exportar reportes"},
}

func validateRoleName(name string) error {
	if !roleNameRegex.MatchString(name) {
		return ErrInvalidRoleName
	}
	if len(name) > 100 {
		return ErrRoleNameTooLong
	}
	return nil
}

func toRoleResponse(role repository.Role, perms []string, usersCount int) dto.RoleResponse {
	if perms == nil {
		perms = []string{}
	}
	return dto.RoleResponse{
		ID:           role.ID,
		Name:         role.Name,
		Description:  role.Description,
		InheritsFrom: role.InheritsFrom,
		System:       role.System,
		Permissions:  perms,
		UsersCount:   usersCount,
		CreatedAt:    role.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:    role.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
}
