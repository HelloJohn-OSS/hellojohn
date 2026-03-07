// repos_extended.go — MFA, Consent, Scope, RBAC repositories
package pg

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// ─── MFARepository ───

type mfaRepo struct{ pool *pgxpool.Pool }

func (r *mfaRepo) UpsertTOTP(ctx context.Context, userID, secretEnc string) error {
	const query = `
		INSERT INTO mfa_totp (user_id, secret_encrypted, created_at, updated_at)
		VALUES ($1, $2, NOW(), NOW())
		ON CONFLICT (user_id) DO UPDATE SET secret_encrypted = $2, updated_at = NOW()
	`
	_, err := r.pool.Exec(ctx, query, userID, secretEnc)
	return err
}

func (r *mfaRepo) ConfirmTOTP(ctx context.Context, userID string) error {
	const query = `UPDATE mfa_totp SET confirmed_at = NOW(), updated_at = NOW() WHERE user_id = $1`
	_, err := r.pool.Exec(ctx, query, userID)
	return err
}

func (r *mfaRepo) GetTOTP(ctx context.Context, userID string) (*repository.MFATOTP, error) {
	const query = `
		SELECT user_id, secret_encrypted, confirmed_at, last_used_at, created_at, updated_at
		FROM mfa_totp WHERE user_id = $1
	`
	var mfa repository.MFATOTP
	err := r.pool.QueryRow(ctx, query, userID).Scan(
		&mfa.UserID, &mfa.SecretEncrypted, &mfa.ConfirmedAt, &mfa.LastUsedAt, &mfa.CreatedAt, &mfa.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	return &mfa, err
}

func (r *mfaRepo) UpdateTOTPUsedAt(ctx context.Context, userID string) error {
	const query = `UPDATE mfa_totp SET last_used_at = NOW(), updated_at = NOW() WHERE user_id = $1`
	_, err := r.pool.Exec(ctx, query, userID)
	return err
}

func (r *mfaRepo) DisableTOTP(ctx context.Context, userID string) error {
	const query = `DELETE FROM mfa_totp WHERE user_id = $1`
	_, err := r.pool.Exec(ctx, query, userID)
	return err
}

func (r *mfaRepo) SetRecoveryCodes(ctx context.Context, userID string, hashes []string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Eliminar anteriores
	_, err = tx.Exec(ctx, `DELETE FROM mfa_recovery_code WHERE user_id = $1`, userID)
	if err != nil {
		return err
	}

	// Insertar nuevos
	for _, hash := range hashes {
		_, err = tx.Exec(ctx,
			`INSERT INTO mfa_recovery_code (user_id, code_hash, created_at) VALUES ($1, $2, NOW())`,
			userID, hash)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (r *mfaRepo) DeleteRecoveryCodes(ctx context.Context, userID string) error {
	const query = `DELETE FROM mfa_recovery_code WHERE user_id = $1`
	_, err := r.pool.Exec(ctx, query, userID)
	return err
}

func (r *mfaRepo) UseRecoveryCode(ctx context.Context, userID, hash string) (bool, error) {
	const query = `
		DELETE FROM mfa_recovery_code WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL
	`
	tag, err := r.pool.Exec(ctx, query, userID, hash)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (r *mfaRepo) AddTrustedDevice(ctx context.Context, userID, deviceHash string, expiresAt time.Time) error {
	const query = `
		INSERT INTO mfa_trusted_device (user_id, device_hash, expires_at, created_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (user_id, device_hash) DO UPDATE SET expires_at = $3
	`
	_, err := r.pool.Exec(ctx, query, userID, deviceHash, expiresAt)
	return err
}

func (r *mfaRepo) IsTrustedDevice(ctx context.Context, userID, deviceHash string) (bool, error) {
	const query = `
		SELECT EXISTS (
			SELECT 1 FROM mfa_trusted_device
			WHERE user_id = $1 AND device_hash = $2 AND expires_at > NOW()
		)
	`
	var exists bool
	err := r.pool.QueryRow(ctx, query, userID, deviceHash).Scan(&exists)
	return exists, err
}

// ─── ConsentRepository ───

type consentRepo struct{ pool *pgxpool.Pool }

func (r *consentRepo) Upsert(ctx context.Context, tenantID, userID, clientID string, scopes []string) (*repository.Consent, error) {
	const query = `
		INSERT INTO user_consent (tenant_id, user_id, client_id, scopes, granted_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = $4, updated_at = NOW(), revoked_at = NULL
		RETURNING id, granted_at, updated_at
	`
	consent := &repository.Consent{
		TenantID: tenantID,
		UserID:   userID,
		ClientID: clientID,
		Scopes:   scopes,
	}
	err := r.pool.QueryRow(ctx, query, tenantID, userID, clientID, scopes).Scan(
		&consent.ID, &consent.GrantedAt, &consent.UpdatedAt,
	)
	return consent, err
}

func (r *consentRepo) Get(ctx context.Context, tenantID, userID, clientID string) (*repository.Consent, error) {
	const query = `
		SELECT id, tenant_id, user_id, client_id, scopes, granted_at, updated_at, revoked_at
		FROM user_consent WHERE user_id = $1 AND client_id = $2
	`
	var consent repository.Consent
	err := r.pool.QueryRow(ctx, query, userID, clientID).Scan(
		&consent.ID, &consent.TenantID, &consent.UserID, &consent.ClientID,
		&consent.Scopes, &consent.GrantedAt, &consent.UpdatedAt, &consent.RevokedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	return &consent, err
}

func (r *consentRepo) ListByUser(ctx context.Context, tenantID, userID string, activeOnly bool) ([]repository.Consent, error) {
	var query string
	if activeOnly {
		query = `SELECT id, tenant_id, user_id, client_id, scopes, granted_at, updated_at, revoked_at
		         FROM user_consent WHERE user_id = $1 AND revoked_at IS NULL ORDER BY granted_at DESC`
	} else {
		query = `SELECT id, tenant_id, user_id, client_id, scopes, granted_at, updated_at, revoked_at
		         FROM user_consent WHERE user_id = $1 ORDER BY granted_at DESC`
	}

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var consents []repository.Consent
	for rows.Next() {
		var c repository.Consent
		if err := rows.Scan(&c.ID, &c.TenantID, &c.UserID, &c.ClientID, &c.Scopes, &c.GrantedAt, &c.UpdatedAt, &c.RevokedAt); err != nil {
			return nil, err
		}
		consents = append(consents, c)
	}
	return consents, rows.Err()
}

func (r *consentRepo) Revoke(ctx context.Context, tenantID, userID, clientID string) error {
	const query = `UPDATE user_consent SET revoked_at = NOW() WHERE user_id = $1 AND client_id = $2`
	_, err := r.pool.Exec(ctx, query, userID, clientID)
	return err
}

func (r *consentRepo) ListAll(ctx context.Context, tenantID string, limit, offset int, activeOnly bool) ([]repository.Consent, int, error) {
	// Count query
	var countQuery string
	if activeOnly {
		countQuery = `SELECT COUNT(*) FROM user_consent WHERE tenant_id = $1 AND revoked_at IS NULL`
	} else {
		countQuery = `SELECT COUNT(*) FROM user_consent WHERE tenant_id = $1`
	}

	var total int
	if err := r.pool.QueryRow(ctx, countQuery, tenantID).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Data query
	var dataQuery string
	if activeOnly {
		dataQuery = `
			SELECT id, tenant_id, user_id, client_id, scopes, granted_at, updated_at, revoked_at
			FROM user_consent
			WHERE tenant_id = $1 AND revoked_at IS NULL
			ORDER BY updated_at DESC
			LIMIT $2 OFFSET $3
		`
	} else {
		dataQuery = `
			SELECT id, tenant_id, user_id, client_id, scopes, granted_at, updated_at, revoked_at
			FROM user_consent
			WHERE tenant_id = $1
			ORDER BY updated_at DESC
			LIMIT $2 OFFSET $3
		`
	}

	rows, err := r.pool.Query(ctx, dataQuery, tenantID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var consents []repository.Consent
	for rows.Next() {
		var c repository.Consent
		if err := rows.Scan(&c.ID, &c.TenantID, &c.UserID, &c.ClientID, &c.Scopes, &c.GrantedAt, &c.UpdatedAt, &c.RevokedAt); err != nil {
			return nil, 0, err
		}
		consents = append(consents, c)
	}
	return consents, total, rows.Err()
}

// ─── ScopeRepository ───

type scopeRepo struct{ pool *pgxpool.Pool }

func (r *scopeRepo) Create(ctx context.Context, input repository.ScopeInput) (*repository.Scope, error) {
	const query = `
		INSERT INTO scope (name, description, display_name, claims, depends_on, system, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		RETURNING id, created_at, updated_at
	`
	scope := &repository.Scope{
		Name:        input.Name,
		Description: input.Description,
		DisplayName: input.DisplayName,
		Claims:      input.Claims,
		DependsOn:   input.DependsOn,
		System:      input.System,
	}
	var updatedAt time.Time
	err := r.pool.QueryRow(ctx, query, input.Name, input.Description, input.DisplayName, input.Claims, input.DependsOn, input.System).Scan(&scope.ID, &scope.CreatedAt, &updatedAt)
	if err != nil {
		return nil, fmt.Errorf("pg: create scope: %w", err)
	}
	scope.UpdatedAt = &updatedAt
	return scope, nil
}

func (r *scopeRepo) GetByName(ctx context.Context, name string) (*repository.Scope, error) {
	const query = `
		SELECT id, name, description, COALESCE(display_name, ''), claims, COALESCE(depends_on, ''), system, created_at, updated_at
		FROM scope WHERE name = $1
	`
	var scope repository.Scope
	var updatedAt *time.Time
	err := r.pool.QueryRow(ctx, query, name).Scan(
		&scope.ID, &scope.Name, &scope.Description, &scope.DisplayName, &scope.Claims, &scope.DependsOn, &scope.System, &scope.CreatedAt, &updatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	scope.UpdatedAt = updatedAt
	return &scope, err
}

func (r *scopeRepo) List(ctx context.Context) ([]repository.Scope, error) {
	const query = `
		SELECT id, name, description, COALESCE(display_name, ''), claims, COALESCE(depends_on, ''), system, created_at, updated_at
		FROM scope ORDER BY name
	`
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scopes []repository.Scope
	for rows.Next() {
		var s repository.Scope
		var updatedAt *time.Time
		if err := rows.Scan(&s.ID, &s.Name, &s.Description, &s.DisplayName, &s.Claims, &s.DependsOn, &s.System, &s.CreatedAt, &updatedAt); err != nil {
			return nil, err
		}
		s.UpdatedAt = updatedAt
		scopes = append(scopes, s)
	}
	return scopes, rows.Err()
}

func (r *scopeRepo) Update(ctx context.Context, input repository.ScopeInput) (*repository.Scope, error) {
	const query = `
		UPDATE scope SET description = $2, display_name = $3, claims = $4, depends_on = $5, system = $6, updated_at = NOW()
		WHERE name = $1
		RETURNING id, created_at, updated_at
	`
	scope := &repository.Scope{
		Name:        input.Name,
		Description: input.Description,
		DisplayName: input.DisplayName,
		Claims:      input.Claims,
		DependsOn:   input.DependsOn,
		System:      input.System,
	}
	var updatedAt time.Time
	err := r.pool.QueryRow(ctx, query, input.Name, input.Description, input.DisplayName, input.Claims, input.DependsOn, input.System).Scan(&scope.ID, &scope.CreatedAt, &updatedAt)
	if err != nil {
		return nil, fmt.Errorf("pg: update scope: %w", err)
	}
	scope.UpdatedAt = &updatedAt
	return scope, nil
}

func (r *scopeRepo) Delete(ctx context.Context, scopeID string) error {
	const query = `DELETE FROM scope WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, scopeID)
	return err
}

func (r *scopeRepo) Upsert(ctx context.Context, input repository.ScopeInput) (*repository.Scope, error) {
	const query = `
		INSERT INTO scope (name, description, display_name, claims, depends_on, system, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		ON CONFLICT (name) DO UPDATE SET
			description = $2, display_name = $3, claims = $4, depends_on = $5, system = $6, updated_at = NOW()
		RETURNING id, created_at, updated_at
	`
	scope := &repository.Scope{
		Name:        input.Name,
		Description: input.Description,
		DisplayName: input.DisplayName,
		Claims:      input.Claims,
		DependsOn:   input.DependsOn,
		System:      input.System,
	}
	var updatedAt time.Time
	err := r.pool.QueryRow(ctx, query, input.Name, input.Description, input.DisplayName, input.Claims, input.DependsOn, input.System).Scan(&scope.ID, &scope.CreatedAt, &updatedAt)
	if err != nil {
		return nil, fmt.Errorf("pg: upsert scope: %w", err)
	}
	scope.UpdatedAt = &updatedAt
	return scope, nil
}

// ─── RBACRepository ───

type rbacRepo struct{ pool *pgxpool.Pool }

func (r *rbacRepo) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	const query = `SELECT role_name FROM rbac_user_role WHERE user_id = $1`
	rows, err := r.pool.Query(ctx, query, userID)
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

func (r *rbacRepo) GetUserPermissions(ctx context.Context, userID string) ([]string, error) {
	const query = `
		SELECT DISTINCT perm
		FROM rbac_user_role ur
		JOIN rbac_role r ON r.name = ur.role_name
		CROSS JOIN UNNEST(r.permissions) AS perm
		WHERE ur.user_id = $1
	`
	rows, err := r.pool.Query(ctx, query, userID)
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

func (r *rbacRepo) AssignRole(ctx context.Context, tenantID, userID, role string) error {
	const query = `
		INSERT INTO rbac_user_role (user_id, role_name, assigned_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT DO NOTHING
	`
	_, err := r.pool.Exec(ctx, query, userID, role)
	return err
}

func (r *rbacRepo) RemoveRole(ctx context.Context, tenantID, userID, role string) error {
	const query = `DELETE FROM rbac_user_role WHERE user_id = $1 AND role_name = $2`
	_, err := r.pool.Exec(ctx, query, userID, role)
	return err
}

func (r *rbacRepo) GetRolePermissions(ctx context.Context, tenantID, role string) ([]string, error) {
	const query = `SELECT permissions FROM rbac_role WHERE name = $1`
	var perms []string
	err := r.pool.QueryRow(ctx, query, role).Scan(&perms)
	if err == pgx.ErrNoRows {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	return perms, nil
}

func (r *rbacRepo) AddPermissionToRole(ctx context.Context, tenantID, role, permission string) error {
	const query = `
		UPDATE rbac_role
		SET permissions = array_append(permissions, $2)
		WHERE name = $1 AND NOT ($2 = ANY(permissions))
	`
	_, err := r.pool.Exec(ctx, query, role, permission)
	return err
}

func (r *rbacRepo) RemovePermissionFromRole(ctx context.Context, tenantID, role, permission string) error {
	const query = `
		UPDATE rbac_role
		SET permissions = array_remove(permissions, $2)
		WHERE name = $1
	`
	_, err := r.pool.Exec(ctx, query, role, permission)
	return err
}

func (r *rbacRepo) ListRoles(ctx context.Context, tenantID string) ([]repository.Role, error) {
	const query = `
		SELECT COALESCE(id::text, gen_random_uuid()::text), name,
		       COALESCE(description, ''), permissions, inherits_from,
		       system, created_at, updated_at
		FROM rbac_role
		ORDER BY system DESC, name ASC
	`
	rows, err := r.pool.Query(ctx, query)
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
		role.TenantID = tenantID
		role.Description = desc
		role.InheritsFrom = inherits
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (r *rbacRepo) GetRole(ctx context.Context, tenantID, name string) (*repository.Role, error) {
	const query = `
		SELECT COALESCE(id::text, gen_random_uuid()::text), name,
		       COALESCE(description, ''), permissions, inherits_from,
		       system, created_at, updated_at
		FROM rbac_role
		WHERE name = $1
	`
	var role repository.Role
	var desc string
	var inherits *string
	err := r.pool.QueryRow(ctx, query, name).Scan(
		&role.ID, &role.Name, &desc, &role.Permissions, &inherits, &role.System, &role.CreatedAt, &role.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	role.TenantID = tenantID
	role.Description = desc
	role.InheritsFrom = inherits
	return &role, nil
}

func (r *rbacRepo) CreateRole(ctx context.Context, tenantID string, input repository.RoleInput) (*repository.Role, error) {
	const query = `
		INSERT INTO rbac_role (name, description, inherits_from, system, created_at, updated_at)
		VALUES ($1, $2, $3, false, NOW(), NOW())
		RETURNING COALESCE(id::text, gen_random_uuid()::text), created_at, updated_at
	`
	role := &repository.Role{
		TenantID:     tenantID,
		Name:         input.Name,
		Description:  input.Description,
		Permissions:  []string{},
		InheritsFrom: input.InheritsFrom,
		System:       false,
	}
	err := r.pool.QueryRow(ctx, query, input.Name, input.Description, input.InheritsFrom).
		Scan(&role.ID, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("pg: create role: %w", err)
	}
	return role, nil
}

func (r *rbacRepo) UpdateRole(ctx context.Context, tenantID, name string, input repository.RoleInput) (*repository.Role, error) {
	const query = `
		UPDATE rbac_role
		SET description = COALESCE($2, description),
			inherits_from = $3,
			updated_at = NOW()
		WHERE name = $1 AND system = false
		RETURNING COALESCE(id::text, gen_random_uuid()::text), name,
		          COALESCE(description, ''), permissions, inherits_from,
		          system, created_at, updated_at
	`
	var role repository.Role
	var desc string
	var inherits *string
	err := r.pool.QueryRow(ctx, query, name, input.Description, input.InheritsFrom).Scan(
		&role.ID, &role.Name, &desc, &role.Permissions, &inherits, &role.System, &role.CreatedAt, &role.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("pg: update role: %w", err)
	}
	role.TenantID = tenantID
	role.Description = desc
	role.InheritsFrom = inherits
	return &role, nil
}

func (r *rbacRepo) DeleteRole(ctx context.Context, tenantID, name string) error {
	// Verificar que no sea sistema
	role, err := r.GetRole(ctx, tenantID, name)
	if err != nil {
		return err
	}
	if role.System {
		return fmt.Errorf("cannot delete system role: %s", name)
	}

	// Eliminar asignaciones de usuarios
	_, _ = r.pool.Exec(ctx, `DELETE FROM rbac_user_role WHERE role_name = $1`, name)

	// Eliminar rol (permissions se eliminan automáticamente al ser columna del rol)
	_, err = r.pool.Exec(ctx, `DELETE FROM rbac_role WHERE name = $1`, name)
	return err
}

func (r *rbacRepo) GetRoleUsersCount(ctx context.Context, tenantID, role string) (int, error) {
	const query = `SELECT COUNT(*) FROM rbac_user_role WHERE role_name = $1`
	var count int
	err := r.pool.QueryRow(ctx, query, role).Scan(&count)
	return count, err
}
