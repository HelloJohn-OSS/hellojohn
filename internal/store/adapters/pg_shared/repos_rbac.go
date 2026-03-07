package pg_shared

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// ─── sharedRBACRepo ──────────────────────────────────────────────

// sharedRBACRepo implements repository.RBACRepository for Global Data Plane.
// CRITICAL: rbac_role has composite PK (tenant_id, name). All JOINs must
// match on BOTH tenant_id and role_name.
type sharedRBACRepo struct {
	pool     *pgxpool.Pool
	tenantID uuid.UUID
}

func (r *sharedRBACRepo) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	const query = `SELECT role_name FROM rbac_user_role WHERE tenant_id = $1 AND user_id = $2`
	rows, err := r.pool.Query(ctx, query, r.tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (r *sharedRBACRepo) GetUserPermissions(ctx context.Context, userID string) ([]string, error) {
	// CRITICAL: JOIN on BOTH tenant_id AND role_name for composite PK
	const query = `
		SELECT DISTINCT perm
		FROM rbac_user_role ur
		JOIN rbac_role ro ON ro.tenant_id = ur.tenant_id AND ro.name = ur.role_name
		CROSS JOIN UNNEST(ro.permissions) AS perm
		WHERE ur.tenant_id = $1 AND ur.user_id = $2
	`
	rows, err := r.pool.Query(ctx, query, r.tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []string
	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err != nil {
			return nil, err
		}
		perms = append(perms, perm)
	}
	return perms, rows.Err()
}

func (r *sharedRBACRepo) AssignRole(ctx context.Context, _ string, userID, role string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO rbac_user_role (tenant_id, user_id, role_name, assigned_at) VALUES ($1, $2, $3, NOW()) ON CONFLICT DO NOTHING`,
			r.tenantID, userID, role)
		return err
	})
}

func (r *sharedRBACRepo) RemoveRole(ctx context.Context, _ string, userID, role string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM rbac_user_role WHERE tenant_id = $1 AND user_id = $2 AND role_name = $3`,
			r.tenantID, userID, role)
		return err
	})
}

func (r *sharedRBACRepo) GetRolePermissions(ctx context.Context, _ string, role string) ([]string, error) {
	const query = `SELECT permissions FROM rbac_role WHERE tenant_id = $1 AND name = $2`
	var perms []string
	err := r.pool.QueryRow(ctx, query, r.tenantID, role).Scan(&perms)
	if errors.Is(err, pgx.ErrNoRows) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	return perms, nil
}

func (r *sharedRBACRepo) AddPermissionToRole(ctx context.Context, _ string, role, permission string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE rbac_role
			SET permissions = array_append(permissions, $3)
			WHERE tenant_id = $1 AND name = $2 AND NOT ($3 = ANY(permissions))
		`, r.tenantID, role, permission)
		return err
	})
}

func (r *sharedRBACRepo) RemovePermissionFromRole(ctx context.Context, _ string, role, permission string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE rbac_role
			SET permissions = array_remove(permissions, $3)
			WHERE tenant_id = $1 AND name = $2
		`, r.tenantID, role, permission)
		return err
	})
}

func (r *sharedRBACRepo) ListRoles(ctx context.Context, _ string) ([]repository.Role, error) {
	const query = `
		SELECT id::text, name,
		       COALESCE(description, ''), permissions, inherits_from,
		       system, created_at, updated_at
		FROM rbac_role
		WHERE tenant_id = $1
		ORDER BY system DESC, name ASC
	`
	rows, err := r.pool.Query(ctx, query, r.tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []repository.Role
	for rows.Next() {
		var role repository.Role
		var desc string
		var inherits *string
		if err := rows.Scan(&role.ID, &role.Name, &desc, &role.Permissions, &inherits, &role.System, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, err
		}
		role.TenantID = r.tenantID.String()
		role.Description = desc
		role.InheritsFrom = inherits
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (r *sharedRBACRepo) GetRole(ctx context.Context, _ string, name string) (*repository.Role, error) {
	const query = `
		SELECT id::text, name,
		       COALESCE(description, ''), permissions, inherits_from,
		       system, created_at, updated_at
		FROM rbac_role
		WHERE tenant_id = $1 AND name = $2
	`
	var role repository.Role
	var desc string
	var inherits *string
	err := r.pool.QueryRow(ctx, query, r.tenantID, name).Scan(
		&role.ID, &role.Name, &desc, &role.Permissions, &inherits, &role.System, &role.CreatedAt, &role.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	role.TenantID = r.tenantID.String()
	role.Description = desc
	role.InheritsFrom = inherits
	return &role, nil
}

func (r *sharedRBACRepo) CreateRole(ctx context.Context, _ string, input repository.RoleInput) (*repository.Role, error) {
	var role repository.Role
	err := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		const query = `
			INSERT INTO rbac_role (tenant_id, name, description, inherits_from, system, created_at, updated_at)
			VALUES ($1, $2, $3, $4, false, NOW(), NOW())
			RETURNING id::text, created_at, updated_at
		`
		role = repository.Role{
			TenantID:     r.tenantID.String(),
			Name:         input.Name,
			Description:  input.Description,
			Permissions:  []string{},
			InheritsFrom: input.InheritsFrom,
			System:       false,
		}
		return tx.QueryRow(ctx, query, r.tenantID, input.Name, input.Description, input.InheritsFrom).
			Scan(&role.ID, &role.CreatedAt, &role.UpdatedAt)
	})
	if err != nil {
		return nil, fmt.Errorf("pg_shared: create role: %w", err)
	}
	return &role, nil
}

func (r *sharedRBACRepo) UpdateRole(ctx context.Context, _ string, name string, input repository.RoleInput) (*repository.Role, error) {
	var role repository.Role
	err := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		const query = `
			UPDATE rbac_role
			SET description = COALESCE($3, description),
				inherits_from = $4,
				updated_at = NOW()
			WHERE tenant_id = $1 AND name = $2 AND system = false
			RETURNING id::text, name,
			          COALESCE(description, ''), permissions, inherits_from,
			          system, created_at, updated_at
		`
		var desc string
		var inherits *string
		err := tx.QueryRow(ctx, query, r.tenantID, name, input.Description, input.InheritsFrom).Scan(
			&role.ID, &role.Name, &desc, &role.Permissions, &inherits, &role.System, &role.CreatedAt, &role.UpdatedAt,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		role.TenantID = r.tenantID.String()
		role.Description = desc
		role.InheritsFrom = inherits
		return err
	})
	if err != nil {
		return nil, err
	}
	return &role, nil
}

func (r *sharedRBACRepo) DeleteRole(ctx context.Context, _ string, name string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		// Delete user assignments for non-system roles atomically.
		tag, err := tx.Exec(ctx,
			`DELETE FROM rbac_user_role WHERE tenant_id = $1 AND role_name = $2
			 AND EXISTS (SELECT 1 FROM rbac_role WHERE tenant_id = $1 AND name = $2 AND system = false)`,
			r.tenantID, name)
		if err != nil {
			return err
		}
		// Delete role, enforcing system = false atomically.
		dtag, err := tx.Exec(ctx,
			`DELETE FROM rbac_role WHERE tenant_id = $1 AND name = $2 AND system = false`,
			r.tenantID, name)
		if err != nil {
			return err
		}
		_ = tag
		if dtag.RowsAffected() == 0 {
			// Could be not found or is a system role; check which.
			// Use tx (within the RLS-scoped transaction) to avoid bypassing RLS.
			var sys bool
			qErr := tx.QueryRow(ctx,
				`SELECT system FROM rbac_role WHERE tenant_id = $1 AND name = $2`,
				r.tenantID, name).Scan(&sys)
			if errors.Is(qErr, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			if qErr == nil && sys {
				return fmt.Errorf("cannot delete system role: %s", name)
			}
			return qErr
		}
		return nil
	})
}

func (r *sharedRBACRepo) GetRoleUsersCount(ctx context.Context, _ string, role string) (int, error) {
	const query = `SELECT COUNT(*) FROM rbac_user_role WHERE tenant_id = $1 AND role_name = $2`
	var count int
	err := r.pool.QueryRow(ctx, query, r.tenantID, role).Scan(&count)
	return count, err
}
