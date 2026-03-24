package mysql_shared

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// ─── sharedRBACRepo ──────────────────────────────────────────────

// sharedRBACRepo implements repository.RBACRepository for Global Data Plane (MySQL).
// CRITICAL: rbac_role has composite PK (tenant_id, name). All JOINs must
// match on BOTH tenant_id and role_name.
type sharedRBACRepo struct {
	db       *sql.DB
	tenantID uuid.UUID
}

func (r *sharedRBACRepo) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	const query = `SELECT role_name FROM rbac_user_role WHERE tenant_id = ? AND user_id = ?`
	rows, err := r.db.QueryContext(ctx, query, r.tenantID.String(), userID)
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
	// CRITICAL: JOIN on BOTH tenant_id AND role_name for composite PK.
	// MySQL doesn't have UNNEST — use JSON_TABLE to expand the JSON permissions array.
	const query = `
		SELECT DISTINCT jt.perm
		FROM rbac_user_role ur
		JOIN rbac_role ro ON ro.tenant_id = ur.tenant_id AND ro.name = ur.role_name
		JOIN JSON_TABLE(ro.permissions, '$[*]' COLUMNS (perm VARCHAR(255) PATH '$')) jt
		WHERE ur.tenant_id = ? AND ur.user_id = ?
	`
	rows, err := r.db.QueryContext(ctx, query, r.tenantID.String(), userID)
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
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`INSERT IGNORE INTO rbac_user_role (tenant_id, user_id, role_name, assigned_at) VALUES (?, ?, ?, NOW())`,
		r.tenantID.String(), userID, role)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *sharedRBACRepo) RemoveRole(ctx context.Context, _ string, userID, role string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`DELETE FROM rbac_user_role WHERE tenant_id = ? AND user_id = ? AND role_name = ?`,
		r.tenantID.String(), userID, role)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *sharedRBACRepo) GetRolePermissions(ctx context.Context, _ string, role string) ([]string, error) {
	const query = `SELECT permissions FROM rbac_role WHERE tenant_id = ? AND name = ?`
	var raw []byte
	err := r.db.QueryRowContext(ctx, query, r.tenantID.String(), role).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var perms []string
	if err := json.Unmarshal(raw, &perms); err != nil {
		return nil, fmt.Errorf("mysql_shared: unmarshal permissions: %w", err)
	}
	return perms, nil
}

func (r *sharedRBACRepo) AddPermissionToRole(ctx context.Context, _ string, role, permission string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	// Read current permissions.
	var raw []byte
	err = tx.QueryRowContext(ctx,
		`SELECT permissions FROM rbac_role WHERE tenant_id = ? AND name = ?`,
		r.tenantID.String(), role).Scan(&raw)
	if err != nil {
		return err
	}

	var perms []string
	if err := json.Unmarshal(raw, &perms); err != nil {
		return fmt.Errorf("mysql_shared: unmarshal permissions: %w", err)
	}

	// Check if already present.
	for _, p := range perms {
		if p == permission {
			return tx.Commit() // Already exists, no-op.
		}
	}

	perms = append(perms, permission)
	updated, err := json.Marshal(perms)
	if err != nil {
		return fmt.Errorf("mysql_shared: marshal permissions: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`UPDATE rbac_role SET permissions = ? WHERE tenant_id = ? AND name = ?`,
		updated, r.tenantID.String(), role)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *sharedRBACRepo) RemovePermissionFromRole(ctx context.Context, _ string, role, permission string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	// Read current permissions.
	var raw []byte
	err = tx.QueryRowContext(ctx,
		`SELECT permissions FROM rbac_role WHERE tenant_id = ? AND name = ?`,
		r.tenantID.String(), role).Scan(&raw)
	if err != nil {
		return err
	}

	var perms []string
	if err := json.Unmarshal(raw, &perms); err != nil {
		return fmt.Errorf("mysql_shared: unmarshal permissions: %w", err)
	}

	// Remove the permission.
	filtered := make([]string, 0, len(perms))
	for _, p := range perms {
		if p != permission {
			filtered = append(filtered, p)
		}
	}

	updated, err := json.Marshal(filtered)
	if err != nil {
		return fmt.Errorf("mysql_shared: marshal permissions: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`UPDATE rbac_role SET permissions = ? WHERE tenant_id = ? AND name = ?`,
		updated, r.tenantID.String(), role)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *sharedRBACRepo) ListRoles(ctx context.Context, _ string) ([]repository.Role, error) {
	const query = `
		SELECT id, name,
		       COALESCE(description, ''), permissions, inherits_from,
		       system, created_at, updated_at
		FROM rbac_role
		WHERE tenant_id = ?
		ORDER BY system DESC, name ASC
	`
	rows, err := r.db.QueryContext(ctx, query, r.tenantID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []repository.Role
	for rows.Next() {
		var role repository.Role
		var desc string
		var inherits *string
		var rawPerms []byte
		if err := rows.Scan(&role.ID, &role.Name, &desc, &rawPerms, &inherits, &role.System, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(rawPerms, &role.Permissions); err != nil {
			return nil, fmt.Errorf("mysql_shared: unmarshal permissions: %w", err)
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
		SELECT id, name,
		       COALESCE(description, ''), permissions, inherits_from,
		       system, created_at, updated_at
		FROM rbac_role
		WHERE tenant_id = ? AND name = ?
	`
	var role repository.Role
	var desc string
	var inherits *string
	var rawPerms []byte
	err := r.db.QueryRowContext(ctx, query, r.tenantID.String(), name).Scan(
		&role.ID, &role.Name, &desc, &rawPerms, &inherits, &role.System, &role.CreatedAt, &role.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(rawPerms, &role.Permissions); err != nil {
		return nil, fmt.Errorf("mysql_shared: unmarshal permissions: %w", err)
	}
	role.TenantID = r.tenantID.String()
	role.Description = desc
	role.InheritsFrom = inherits
	return &role, nil
}

func (r *sharedRBACRepo) CreateRole(ctx context.Context, _ string, input repository.RoleInput) (*repository.Role, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	// MySQL doesn't support RETURNING — insert then select.
	_, err = tx.ExecContext(ctx, `
		INSERT INTO rbac_role (tenant_id, name, description, inherits_from, system, created_at, updated_at)
		VALUES (?, ?, ?, ?, false, NOW(), NOW())
	`, r.tenantID.String(), input.Name, input.Description, input.InheritsFrom)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: create role: %w", err)
	}

	role := repository.Role{
		TenantID:     r.tenantID.String(),
		Name:         input.Name,
		Description:  input.Description,
		Permissions:  []string{},
		InheritsFrom: input.InheritsFrom,
		System:       false,
	}

	err = tx.QueryRowContext(ctx,
		`SELECT id, created_at, updated_at FROM rbac_role WHERE tenant_id = ? AND name = ?`,
		r.tenantID.String(), input.Name).Scan(&role.ID, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: create role select: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &role, nil
}

func (r *sharedRBACRepo) UpdateRole(ctx context.Context, _ string, name string, input repository.RoleInput) (*repository.Role, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	// MySQL doesn't support RETURNING — update then select.
	result, err := tx.ExecContext(ctx, `
		UPDATE rbac_role
		SET description = COALESCE(?, description),
		    inherits_from = ?,
		    updated_at = NOW()
		WHERE tenant_id = ? AND name = ? AND system = false
	`, input.Description, input.InheritsFrom, r.tenantID.String(), name)
	if err != nil {
		return nil, err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if affected == 0 {
		// Check if it exists at all (might be system or not found).
		var exists bool
		_ = tx.QueryRowContext(ctx,
			`SELECT 1 FROM rbac_role WHERE tenant_id = ? AND name = ?`,
			r.tenantID.String(), name).Scan(&exists)
		if !exists {
			return nil, repository.ErrNotFound
		}
		// Exists but system = true: still return current state (PG version returns the row via RETURNING).
		// For system roles the UPDATE matched 0 rows, so treat as not found (same PG behavior).
		return nil, repository.ErrNotFound
	}

	var role repository.Role
	var desc string
	var inherits *string
	var rawPerms []byte
	err = tx.QueryRowContext(ctx, `
		SELECT id, name,
		       COALESCE(description, ''), permissions, inherits_from,
		       system, created_at, updated_at
		FROM rbac_role
		WHERE tenant_id = ? AND name = ?
	`, r.tenantID.String(), name).Scan(
		&role.ID, &role.Name, &desc, &rawPerms, &inherits, &role.System, &role.CreatedAt, &role.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(rawPerms, &role.Permissions); err != nil {
		return nil, fmt.Errorf("mysql_shared: unmarshal permissions: %w", err)
	}
	role.TenantID = r.tenantID.String()
	role.Description = desc
	role.InheritsFrom = inherits

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &role, nil
}

func (r *sharedRBACRepo) DeleteRole(ctx context.Context, _ string, name string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	// Delete user assignments for non-system roles atomically.
	_, err = tx.ExecContext(ctx,
		`DELETE FROM rbac_user_role WHERE tenant_id = ? AND role_name = ?
		 AND EXISTS (SELECT 1 FROM rbac_role WHERE tenant_id = ? AND name = ? AND system = false)`,
		r.tenantID.String(), name, r.tenantID.String(), name)
	if err != nil {
		return err
	}

	// Delete role, enforcing system = false atomically.
	result, err := tx.ExecContext(ctx,
		`DELETE FROM rbac_role WHERE tenant_id = ? AND name = ? AND system = false`,
		r.tenantID.String(), name)
	if err != nil {
		return err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		// Could be not found or is a system role; check which.
		var sys bool
		qErr := tx.QueryRowContext(ctx,
			`SELECT system FROM rbac_role WHERE tenant_id = ? AND name = ?`,
			r.tenantID.String(), name).Scan(&sys)
		if errors.Is(qErr, sql.ErrNoRows) {
			return repository.ErrNotFound
		}
		if qErr == nil && sys {
			return fmt.Errorf("cannot delete system role: %s", name)
		}
		return qErr
	}
	return tx.Commit()
}

func (r *sharedRBACRepo) GetRoleUsersCount(ctx context.Context, _ string, role string) (int, error) {
	const query = `SELECT COUNT(*) FROM rbac_user_role WHERE tenant_id = ? AND role_name = ?`
	var count int
	err := r.db.QueryRowContext(ctx, query, r.tenantID.String(), role).Scan(&count)
	return count, err
}
