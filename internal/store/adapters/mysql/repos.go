// Package mysql implementa los repositorios secundarios para MySQL.
// Este archivo contiene: MFA, Consent, Scope, RBAC, EmailToken, Identity, Schema
package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// ─────────────────────────────────────────────────────────────────────────────
// MFARepository
// ─────────────────────────────────────────────────────────────────────────────

var _ repository.MFARepository = (*mfaRepo)(nil)

func (r *mfaRepo) UpsertTOTP(ctx context.Context, userID, secretEnc string) error {
	// MySQL usa INSERT ... ON DUPLICATE KEY UPDATE
	const query = `
		INSERT INTO mfa_totp (user_id, secret_encrypted, created_at, updated_at)
		VALUES (?, ?, NOW(), NOW())
		ON DUPLICATE KEY UPDATE secret_encrypted = VALUES(secret_encrypted), updated_at = NOW()
	`
	_, err := r.db.ExecContext(ctx, query, userID, secretEnc)
	return err
}

func (r *mfaRepo) ConfirmTOTP(ctx context.Context, userID string) error {
	const query = `UPDATE mfa_totp SET confirmed_at = NOW(), updated_at = NOW() WHERE user_id = ?`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

func (r *mfaRepo) GetTOTP(ctx context.Context, userID string) (*repository.MFATOTP, error) {
	const query = `
		SELECT user_id, secret_encrypted, confirmed_at, last_used_at, created_at, updated_at
		FROM mfa_totp WHERE user_id = ?
	`
	var mfa repository.MFATOTP
	var confirmedAt, lastUsedAt sql.NullTime
	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&mfa.UserID, &mfa.SecretEncrypted, &confirmedAt, &lastUsedAt, &mfa.CreatedAt, &mfa.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	mfa.ConfirmedAt = nullTimeToPtr(confirmedAt)
	mfa.LastUsedAt = nullTimeToPtr(lastUsedAt)
	return &mfa, nil
}

func (r *mfaRepo) UpdateTOTPUsedAt(ctx context.Context, userID string) error {
	const query = `UPDATE mfa_totp SET last_used_at = NOW(), updated_at = NOW() WHERE user_id = ?`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

func (r *mfaRepo) DisableTOTP(ctx context.Context, userID string) error {
	const query = `DELETE FROM mfa_totp WHERE user_id = ?`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

func (r *mfaRepo) SetRecoveryCodes(ctx context.Context, userID string, hashes []string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Eliminar anteriores
	_, err = tx.ExecContext(ctx, `DELETE FROM mfa_recovery_code WHERE user_id = ?`, userID)
	if err != nil {
		return err
	}

	// Insertar nuevos
	for _, hash := range hashes {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO mfa_recovery_code (user_id, code_hash, created_at) VALUES (?, ?, NOW())`,
			userID, hash)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *mfaRepo) DeleteRecoveryCodes(ctx context.Context, userID string) error {
	const query = `DELETE FROM mfa_recovery_code WHERE user_id = ?`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

func (r *mfaRepo) UseRecoveryCode(ctx context.Context, userID, hash string) (bool, error) {
	const query = `DELETE FROM mfa_recovery_code WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`
	result, err := r.db.ExecContext(ctx, query, userID, hash)
	if err != nil {
		return false, err
	}
	rowsAffected, _ := result.RowsAffected()
	return rowsAffected > 0, nil
}

func (r *mfaRepo) AddTrustedDevice(ctx context.Context, userID, deviceHash string, expiresAt time.Time) error {
	const query = `
		INSERT INTO mfa_trusted_device (user_id, device_hash, expires_at, created_at)
		VALUES (?, ?, ?, NOW())
		ON DUPLICATE KEY UPDATE expires_at = VALUES(expires_at)
	`
	_, err := r.db.ExecContext(ctx, query, userID, deviceHash, expiresAt)
	return err
}

func (r *mfaRepo) IsTrustedDevice(ctx context.Context, userID, deviceHash string) (bool, error) {
	const query = `
		SELECT EXISTS (
			SELECT 1 FROM mfa_trusted_device
			WHERE user_id = ? AND device_hash = ? AND expires_at > NOW()
		)
	`
	var exists bool
	err := r.db.QueryRowContext(ctx, query, userID, deviceHash).Scan(&exists)
	return exists, err
}

// ─────────────────────────────────────────────────────────────────────────────
// ConsentRepository
// ─────────────────────────────────────────────────────────────────────────────

var _ repository.ConsentRepository = (*consentRepo)(nil)

func (r *consentRepo) Upsert(ctx context.Context, tenantID, userID, clientID string, scopes []string) (*repository.Consent, error) {
	now := time.Now()
	scopesJSON, _ := json.Marshal(scopes)

	// Intentar insertar primero
	consentID := uuid.New().String()
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO user_consent (id, tenant_id, user_id, client_id, scopes, granted_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE scopes = VALUES(scopes), updated_at = VALUES(updated_at), revoked_at = NULL
	`, consentID, tenantID, userID, clientID, scopesJSON, now, now)

	if err != nil {
		return nil, fmt.Errorf("mysql: upsert consent: %w", err)
	}

	// Obtener el consent actualizado
	return r.Get(ctx, tenantID, userID, clientID)
}

func (r *consentRepo) Get(ctx context.Context, tenantID, userID, clientID string) (*repository.Consent, error) {
	const query = `
		SELECT id, tenant_id, user_id, client_id, scopes, granted_at, updated_at, revoked_at
		FROM user_consent WHERE user_id = ? AND client_id = ?
	`
	var consent repository.Consent
	var scopesJSON []byte
	var revokedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, userID, clientID).Scan(
		&consent.ID, &consent.TenantID, &consent.UserID, &consent.ClientID,
		&scopesJSON, &consent.GrantedAt, &consent.UpdatedAt, &revokedAt,
	)
	if err == sql.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	consent.Scopes = jsonToStrings(scopesJSON)
	consent.RevokedAt = nullTimeToPtr(revokedAt)
	return &consent, nil
}

func (r *consentRepo) ListByUser(ctx context.Context, tenantID, userID string, activeOnly bool) ([]repository.Consent, error) {
	var query string
	if activeOnly {
		query = `SELECT id, tenant_id, user_id, client_id, scopes, granted_at, updated_at, revoked_at
		         FROM user_consent WHERE user_id = ? AND revoked_at IS NULL ORDER BY granted_at DESC`
	} else {
		query = `SELECT id, tenant_id, user_id, client_id, scopes, granted_at, updated_at, revoked_at
		         FROM user_consent WHERE user_id = ? ORDER BY granted_at DESC`
	}

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var consents []repository.Consent
	for rows.Next() {
		var c repository.Consent
		var scopesJSON []byte
		var revokedAt sql.NullTime
		if err := rows.Scan(&c.ID, &c.TenantID, &c.UserID, &c.ClientID, &scopesJSON, &c.GrantedAt, &c.UpdatedAt, &revokedAt); err != nil {
			return nil, err
		}
		c.Scopes = jsonToStrings(scopesJSON)
		c.RevokedAt = nullTimeToPtr(revokedAt)
		consents = append(consents, c)
	}
	return consents, rows.Err()
}

func (r *consentRepo) ListAll(ctx context.Context, tenantID string, limit, offset int, activeOnly bool) ([]repository.Consent, int, error) {
	// Count query
	var countQuery string
	if activeOnly {
		countQuery = `SELECT COUNT(*) FROM user_consent WHERE tenant_id = ? AND revoked_at IS NULL`
	} else {
		countQuery = `SELECT COUNT(*) FROM user_consent WHERE tenant_id = ?`
	}

	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, tenantID).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Data query
	var dataQuery string
	if activeOnly {
		dataQuery = `
			SELECT id, tenant_id, user_id, client_id, scopes, granted_at, updated_at, revoked_at
			FROM user_consent WHERE tenant_id = ? AND revoked_at IS NULL
			ORDER BY updated_at DESC LIMIT ? OFFSET ?`
	} else {
		dataQuery = `
			SELECT id, tenant_id, user_id, client_id, scopes, granted_at, updated_at, revoked_at
			FROM user_consent WHERE tenant_id = ?
			ORDER BY updated_at DESC LIMIT ? OFFSET ?`
	}

	rows, err := r.db.QueryContext(ctx, dataQuery, tenantID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var consents []repository.Consent
	for rows.Next() {
		var c repository.Consent
		var scopesJSON []byte
		var revokedAt sql.NullTime
		if err := rows.Scan(&c.ID, &c.TenantID, &c.UserID, &c.ClientID, &scopesJSON, &c.GrantedAt, &c.UpdatedAt, &revokedAt); err != nil {
			return nil, 0, err
		}
		c.Scopes = jsonToStrings(scopesJSON)
		c.RevokedAt = nullTimeToPtr(revokedAt)
		consents = append(consents, c)
	}
	return consents, total, rows.Err()
}

func (r *consentRepo) Revoke(ctx context.Context, tenantID, userID, clientID string) error {
	const query = `UPDATE user_consent SET revoked_at = NOW() WHERE user_id = ? AND client_id = ?`
	_, err := r.db.ExecContext(ctx, query, userID, clientID)
	return err
}

// ─────────────────────────────────────────────────────────────────────────────
// ScopeRepository
// ─────────────────────────────────────────────────────────────────────────────

func (r *scopeRepo) Create(ctx context.Context, input repository.ScopeInput) (*repository.Scope, error) {
	scopeID := uuid.New().String()
	now := time.Now()
	claimsJSON, _ := json.Marshal(input.Claims)

	const query = `
		INSERT INTO scope (id, name, description, display_name, claims, depends_on, system, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := r.db.ExecContext(ctx, query,
		scopeID, input.Name, input.Description, input.DisplayName,
		claimsJSON, input.DependsOn, input.System, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("mysql: create scope: %w", err)
	}

	return &repository.Scope{
		ID:          scopeID,
		Name:        input.Name,
		Description: input.Description,
		DisplayName: input.DisplayName,
		Claims:      input.Claims,
		DependsOn:   input.DependsOn,
		System:      input.System,
		CreatedAt:   now,
		UpdatedAt:   &now,
	}, nil
}

func (r *scopeRepo) GetByName(ctx context.Context, name string) (*repository.Scope, error) {
	const query = `
		SELECT id, name, description, COALESCE(display_name, ''), claims, COALESCE(depends_on, ''), system, created_at, updated_at
		FROM scope WHERE name = ?
	`
	var scope repository.Scope
	var claimsJSON []byte
	var updatedAt sql.NullTime
	err := r.db.QueryRowContext(ctx, query, name).Scan(
		&scope.ID, &scope.Name, &scope.Description, &scope.DisplayName,
		&claimsJSON, &scope.DependsOn, &scope.System, &scope.CreatedAt, &updatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	scope.Claims = jsonToStrings(claimsJSON)
	scope.UpdatedAt = nullTimeToPtr(updatedAt)
	return &scope, nil
}

func (r *scopeRepo) List(ctx context.Context) ([]repository.Scope, error) {
	const query = `
		SELECT id, name, description, COALESCE(display_name, ''), claims, COALESCE(depends_on, ''), system, created_at, updated_at
		FROM scope ORDER BY name
	`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scopes []repository.Scope
	for rows.Next() {
		var s repository.Scope
		var claimsJSON []byte
		var updatedAt sql.NullTime
		if err := rows.Scan(&s.ID, &s.Name, &s.Description, &s.DisplayName, &claimsJSON, &s.DependsOn, &s.System, &s.CreatedAt, &updatedAt); err != nil {
			return nil, err
		}
		s.Claims = jsonToStrings(claimsJSON)
		s.UpdatedAt = nullTimeToPtr(updatedAt)
		scopes = append(scopes, s)
	}
	return scopes, rows.Err()
}

func (r *scopeRepo) Update(ctx context.Context, input repository.ScopeInput) (*repository.Scope, error) {
	claimsJSON, _ := json.Marshal(input.Claims)
	const query = `
		UPDATE scope SET description = ?, display_name = ?, claims = ?, depends_on = ?, system = ?, updated_at = NOW()
		WHERE name = ?
	`
	_, err := r.db.ExecContext(ctx, query,
		input.Description, input.DisplayName, claimsJSON, input.DependsOn, input.System,
		input.Name,
	)
	if err != nil {
		return nil, fmt.Errorf("mysql: update scope: %w", err)
	}
	return r.GetByName(ctx, input.Name)
}

func (r *scopeRepo) Delete(ctx context.Context, name string) error {
	const query = `DELETE FROM scope WHERE name = ?`
	_, err := r.db.ExecContext(ctx, query, name)
	return err
}

func (r *scopeRepo) Upsert(ctx context.Context, input repository.ScopeInput) (*repository.Scope, error) {
	scopeID := uuid.New().String()
	now := time.Now()
	claimsJSON, _ := json.Marshal(input.Claims)

	const query = `
		INSERT INTO scope (id, name, description, display_name, claims, depends_on, system, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			description = VALUES(description), display_name = VALUES(display_name),
			claims = VALUES(claims), depends_on = VALUES(depends_on),
			system = VALUES(system), updated_at = NOW()
	`
	_, err := r.db.ExecContext(ctx, query,
		scopeID, input.Name, input.Description, input.DisplayName,
		claimsJSON, input.DependsOn, input.System, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("mysql: upsert scope: %w", err)
	}

	return r.GetByName(ctx, input.Name)
}

// ─────────────────────────────────────────────────────────────────────────────
// RBACRepository
// ─────────────────────────────────────────────────────────────────────────────

var _ repository.RBACRepository = (*rbacRepo)(nil)

func (r *rbacRepo) GetUserRoles(ctx context.Context, userID string) ([]string, error) {
	const query = `SELECT role_name FROM rbac_user_role WHERE user_id = ?`
	rows, err := r.db.QueryContext(ctx, query, userID)
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
	// MySQL no tiene UNNEST, usamos JSON_TABLE
	const query = `
		SELECT DISTINCT perm.permission
		FROM rbac_user_role ur
		JOIN rbac_role rl ON rl.name = ur.role_name
		JOIN JSON_TABLE(rl.permissions, '$[*]' COLUMNS (permission VARCHAR(255) PATH '$')) AS perm
		WHERE ur.user_id = ?
	`
	rows, err := r.db.QueryContext(ctx, query, userID)
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
		INSERT IGNORE INTO rbac_user_role (user_id, role_name, assigned_at)
		VALUES (?, ?, NOW())
	`
	_, err := r.db.ExecContext(ctx, query, userID, role)
	return err
}

func (r *rbacRepo) RemoveRole(ctx context.Context, tenantID, userID, role string) error {
	const query = `DELETE FROM rbac_user_role WHERE user_id = ? AND role_name = ?`
	_, err := r.db.ExecContext(ctx, query, userID, role)
	return err
}

func (r *rbacRepo) GetRolePermissions(ctx context.Context, tenantID, role string) ([]string, error) {
	const query = `SELECT permissions FROM rbac_role WHERE name = ?`
	var permsJSON []byte
	err := r.db.QueryRowContext(ctx, query, role).Scan(&permsJSON)
	if err == sql.ErrNoRows {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	return jsonToStrings(permsJSON), nil
}

func (r *rbacRepo) AddPermissionToRole(ctx context.Context, tenantID, role, permission string) error {
	// MySQL usa JSON_ARRAY_APPEND
	const query = `
		UPDATE rbac_role
		SET permissions = JSON_ARRAY_APPEND(COALESCE(permissions, '[]'), '$', ?)
		WHERE name = ? AND NOT JSON_CONTAINS(COALESCE(permissions, '[]'), JSON_QUOTE(?))
	`
	_, err := r.db.ExecContext(ctx, query, permission, role, permission)
	return err
}

func (r *rbacRepo) RemovePermissionFromRole(ctx context.Context, tenantID, role, permission string) error {
	// MySQL usa JSON_REMOVE con índice
	const query = `
		UPDATE rbac_role
		SET permissions = JSON_REMOVE(permissions, JSON_UNQUOTE(JSON_SEARCH(permissions, 'one', ?)))
		WHERE name = ? AND JSON_CONTAINS(COALESCE(permissions, '[]'), JSON_QUOTE(?))
	`
	_, err := r.db.ExecContext(ctx, query, permission, role, permission)
	return err
}

func (r *rbacRepo) ListRoles(ctx context.Context, tenantID string) ([]repository.Role, error) {
	const query = `
		SELECT id, name, COALESCE(description, ''), permissions, inherits_from, system, created_at, updated_at
		FROM rbac_role
		ORDER BY system DESC, name ASC
	`
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []repository.Role
	for rows.Next() {
		var role repository.Role
		var desc string
		var permsJSON []byte
		var inherits sql.NullString
		if err := rows.Scan(&role.ID, &role.Name, &desc, &permsJSON, &inherits, &role.System, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, err
		}
		role.TenantID = tenantID
		role.Description = desc
		role.Permissions = jsonToStrings(permsJSON)
		role.InheritsFrom = nullStringToPtr(inherits)
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

func (r *rbacRepo) GetRole(ctx context.Context, tenantID, name string) (*repository.Role, error) {
	const query = `
		SELECT id, name, COALESCE(description, ''), permissions, inherits_from, system, created_at, updated_at
		FROM rbac_role WHERE name = ?
	`
	var role repository.Role
	var desc string
	var permsJSON []byte
	var inherits sql.NullString
	err := r.db.QueryRowContext(ctx, query, name).Scan(
		&role.ID, &role.Name, &desc, &permsJSON, &inherits, &role.System, &role.CreatedAt, &role.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	role.TenantID = tenantID
	role.Description = desc
	role.Permissions = jsonToStrings(permsJSON)
	role.InheritsFrom = nullStringToPtr(inherits)
	return &role, nil
}

func (r *rbacRepo) CreateRole(ctx context.Context, tenantID string, input repository.RoleInput) (*repository.Role, error) {
	roleID := uuid.New().String()
	now := time.Now()

	const query = `
		INSERT INTO rbac_role (id, name, description, inherits_from, system, permissions, created_at, updated_at)
		VALUES (?, ?, ?, ?, false, '[]', ?, ?)
	`
	_, err := r.db.ExecContext(ctx, query, roleID, input.Name, input.Description, input.InheritsFrom, now, now)
	if err != nil {
		return nil, fmt.Errorf("mysql: create role: %w", err)
	}
	return &repository.Role{
		ID:           roleID,
		TenantID:     tenantID,
		Name:         input.Name,
		Description:  input.Description,
		Permissions:  []string{},
		InheritsFrom: input.InheritsFrom,
		System:       false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

func (r *rbacRepo) UpdateRole(ctx context.Context, tenantID, name string, input repository.RoleInput) (*repository.Role, error) {
	const query = `
		UPDATE rbac_role
		SET description = COALESCE(?, description), inherits_from = ?, updated_at = NOW()
		WHERE name = ? AND system = false
	`
	result, err := r.db.ExecContext(ctx, query, input.Description, input.InheritsFrom, name)
	if err != nil {
		return nil, fmt.Errorf("mysql: update role: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return nil, repository.ErrNotFound
	}
	return r.GetRole(ctx, tenantID, name)
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
	_, _ = r.db.ExecContext(ctx, `DELETE FROM rbac_user_role WHERE role_name = ?`, name)

	// Eliminar rol
	_, err = r.db.ExecContext(ctx, `DELETE FROM rbac_role WHERE name = ?`, name)
	return err
}

func (r *rbacRepo) GetRoleUsersCount(ctx context.Context, tenantID, role string) (int, error) {
	const query = `SELECT COUNT(*) FROM rbac_user_role WHERE role_name = ?`
	var count int
	err := r.db.QueryRowContext(ctx, query, role).Scan(&count)
	return count, err
}

// ─────────────────────────────────────────────────────────────────────────────
// EmailTokenRepository
// ─────────────────────────────────────────────────────────────────────────────

var _ repository.EmailTokenRepository = (*emailTokenRepo)(nil)

func tableForType(t repository.EmailTokenType) string {
	switch t {
	case repository.EmailTokenPasswordReset:
		return "password_reset_token"
	default:
		return "email_verification_token"
	}
}

func (r *emailTokenRepo) Create(ctx context.Context, input repository.CreateEmailTokenInput) (*repository.EmailToken, error) {
	table := tableForType(input.Type)
	tokenID := uuid.New().String()

	// Invalidar tokens previos del mismo usuario
	_, err := r.db.ExecContext(ctx,
		`UPDATE `+table+` SET used_at = NOW() WHERE user_id = ? AND used_at IS NULL`,
		input.UserID)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(time.Duration(input.TTLSeconds) * time.Second)
	now := time.Now()

	token := &repository.EmailToken{
		ID:        tokenID,
		TenantID:  input.TenantID,
		UserID:    input.UserID,
		Email:     input.Email,
		Type:      input.Type,
		TokenHash: input.TokenHash,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}

	query := `INSERT INTO ` + table + ` (id, user_id, token_hash, sent_to, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`
	_, err = r.db.ExecContext(ctx, query, tokenID, input.UserID, input.TokenHash, input.Email, expiresAt, now)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (r *emailTokenRepo) GetByHash(ctx context.Context, tokenHash string) (*repository.EmailToken, error) {
	// Buscar en ambas tablas
	for _, t := range []repository.EmailTokenType{repository.EmailTokenVerification, repository.EmailTokenPasswordReset} {
		table := tableForType(t)
		query := `SELECT id, user_id, sent_to, expires_at, used_at, created_at FROM ` + table + ` WHERE token_hash = ?`
		var token repository.EmailToken
		var usedAt sql.NullTime
		token.Type = t
		err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
			&token.ID, &token.UserID, &token.Email, &token.ExpiresAt, &usedAt, &token.CreatedAt,
		)
		if err == nil {
			token.TokenHash = tokenHash
			token.UsedAt = nullTimeToPtr(usedAt)
			return &token, nil
		}
		if err != sql.ErrNoRows {
			return nil, err
		}
	}
	return nil, repository.ErrNotFound
}

func (r *emailTokenRepo) Use(ctx context.Context, tokenHash string) error {
	// Intentar en ambas tablas
	for _, t := range []repository.EmailTokenType{repository.EmailTokenVerification, repository.EmailTokenPasswordReset} {
		table := tableForType(t)
		query := `UPDATE ` + table + ` SET used_at = NOW() WHERE token_hash = ? AND used_at IS NULL AND expires_at > NOW()`
		result, err := r.db.ExecContext(ctx, query, tokenHash)
		if err != nil {
			return err
		}
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected > 0 {
			return nil
		}
	}

	// Verificar si existe pero expiró o ya fue usado
	for _, t := range []repository.EmailTokenType{repository.EmailTokenVerification, repository.EmailTokenPasswordReset} {
		table := tableForType(t)
		var exists bool
		r.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM `+table+` WHERE token_hash = ?)`, tokenHash).Scan(&exists)
		if exists {
			return repository.ErrTokenExpired
		}
	}
	return repository.ErrNotFound
}

func (r *emailTokenRepo) DeleteExpired(ctx context.Context) (int, error) {
	var total int
	for _, t := range []repository.EmailTokenType{repository.EmailTokenVerification, repository.EmailTokenPasswordReset} {
		table := tableForType(t)
		query := `DELETE FROM ` + table + ` WHERE expires_at < NOW() OR used_at IS NOT NULL`
		result, err := r.db.ExecContext(ctx, query)
		if err != nil {
			return total, err
		}
		rowsAffected, _ := result.RowsAffected()
		total += int(rowsAffected)
	}
	return total, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// IdentityRepository
// ─────────────────────────────────────────────────────────────────────────────

var _ repository.IdentityRepository = (*identityRepo)(nil)

func (r *identityRepo) GetByProvider(ctx context.Context, tenantID, provider, providerUserID string) (*repository.SocialIdentity, error) {
	const query = `
		SELECT id, user_id, provider, provider_user_id, email, email_verified, data, created_at, updated_at
		FROM identity WHERE provider = ? AND provider_user_id = ?
	`
	var identity repository.SocialIdentity
	var data []byte
	var updatedAt sql.NullTime
	err := r.db.QueryRowContext(ctx, query, provider, providerUserID).Scan(
		&identity.ID, &identity.UserID, &identity.Provider, &identity.ProviderUserID,
		&identity.Email, &identity.EmailVerified, &data, &identity.CreatedAt, &updatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	identity.TenantID = tenantID
	if updatedAt.Valid {
		identity.UpdatedAt = updatedAt.Time
	}
	return &identity, nil
}

func (r *identityRepo) GetByUserID(ctx context.Context, userID string) ([]repository.SocialIdentity, error) {
	const query = `
		SELECT id, user_id, provider, provider_user_id, email, email_verified, data, created_at, updated_at
		FROM identity WHERE user_id = ? ORDER BY created_at
	`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var identities []repository.SocialIdentity
	for rows.Next() {
		var identity repository.SocialIdentity
		var data []byte
		var updatedAt sql.NullTime
		if err := rows.Scan(
			&identity.ID, &identity.UserID, &identity.Provider, &identity.ProviderUserID,
			&identity.Email, &identity.EmailVerified, &data, &identity.CreatedAt, &updatedAt,
		); err != nil {
			return nil, err
		}
		if updatedAt.Valid {
			identity.UpdatedAt = updatedAt.Time
		}
		identities = append(identities, identity)
	}
	return identities, rows.Err()
}

func (r *identityRepo) Upsert(ctx context.Context, input repository.UpsertSocialIdentityInput) (userID string, isNew bool, err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback()

	// 1. Buscar identidad existente
	var existingIdentityUserID string
	err = tx.QueryRowContext(ctx,
		`SELECT user_id FROM identity WHERE provider = ? AND provider_user_id = ?`,
		input.Provider, input.ProviderUserID,
	).Scan(&existingIdentityUserID)

	if err == nil {
		// Identidad existe → actualizar y retornar
		_, err = tx.ExecContext(ctx, `
			UPDATE identity SET email = ?, email_verified = ?, updated_at = NOW()
			WHERE provider = ? AND provider_user_id = ?`,
			input.Email, input.EmailVerified, input.Provider, input.ProviderUserID,
		)
		if err != nil {
			return "", false, err
		}
		if err := tx.Commit(); err != nil {
			return "", false, err
		}
		return existingIdentityUserID, false, nil
	} else if err != sql.ErrNoRows {
		return "", false, err
	}

	// 2. Identidad no existe. Buscar usuario por email.
	var existingUserID string
	err = tx.QueryRowContext(ctx, `SELECT id FROM app_user WHERE email = ?`, input.Email).Scan(&existingUserID)

	if err == nil {
		userID = existingUserID
		isNew = false
	} else if err == sql.ErrNoRows {
		// Usuario no existe → crear nuevo
		userID = uuid.New().String()
		isNew = true
		now := time.Now()
		_, err = tx.ExecContext(ctx, `
			INSERT INTO app_user (id, email, email_verified, name, picture, created_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			userID, input.Email, input.EmailVerified, input.Name, input.Picture, now,
		)
		if err != nil {
			return "", false, err
		}
	} else {
		return "", false, err
	}

	// 3. Crear identidad
	identityID := uuid.New().String()
	now := time.Now()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO identity (id, user_id, provider, provider_user_id, email, email_verified, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		identityID, userID, input.Provider, input.ProviderUserID, input.Email, input.EmailVerified, now, now,
	)
	if err != nil {
		return "", false, err
	}

	if err := tx.Commit(); err != nil {
		return "", false, err
	}

	return userID, isNew, nil
}

func (r *identityRepo) Link(ctx context.Context, userID string, input repository.UpsertSocialIdentityInput) (*repository.SocialIdentity, error) {
	identityID := uuid.New().String()
	now := time.Now()

	identity := &repository.SocialIdentity{
		ID:             identityID,
		UserID:         userID,
		TenantID:       input.TenantID,
		Provider:       input.Provider,
		ProviderUserID: input.ProviderUserID,
		Email:          input.Email,
		EmailVerified:  input.EmailVerified,
		Name:           input.Name,
		Picture:        input.Picture,
		RawClaims:      input.RawClaims,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	_, err := r.db.ExecContext(ctx, `
		INSERT INTO identity (id, user_id, provider, provider_user_id, email, email_verified, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		identityID, userID, input.Provider, input.ProviderUserID, input.Email, input.EmailVerified, now, now,
	)
	if err != nil {
		return nil, err
	}

	return identity, nil
}

func (r *identityRepo) Unlink(ctx context.Context, userID, provider string) error {
	// Verificar que no sea la última identidad
	var cnt int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM identity WHERE user_id = ?`, userID).Scan(&cnt)
	if err != nil {
		return err
	}
	if cnt <= 1 {
		return repository.ErrLastIdentity
	}

	_, err = r.db.ExecContext(ctx, `DELETE FROM identity WHERE user_id = ? AND provider = ?`, userID, provider)
	return err
}

func (r *identityRepo) UpdateClaims(ctx context.Context, identityID string, claims map[string]any) error {
	claimsJSON, _ := json.Marshal(claims)
	_, err := r.db.ExecContext(ctx,
		`UPDATE identity SET data = ?, updated_at = NOW() WHERE id = ?`,
		claimsJSON, identityID,
	)
	return err
}

// ─────────────────────────────────────────────────────────────────────────────
// SchemaRepository
// ─────────────────────────────────────────────────────────────────────────────

var _ repository.SchemaRepository = (*schemaRepo)(nil)

func (r *schemaRepo) SyncUserFields(ctx context.Context, tenantID string, fields []repository.UserFieldDefinition) error {
	// 1. Ensure custom_data JSON column exists (idempotent)
	var customDataExists int
	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'app_user' AND COLUMN_NAME = 'custom_data'
	`).Scan(&customDataExists); err != nil {
		return fmt.Errorf("mysql: check custom_data column: %w", err)
	}
	if customDataExists == 0 {
		if _, err := r.db.ExecContext(ctx, `ALTER TABLE app_user ADD COLUMN custom_data JSON DEFAULT (JSON_OBJECT())`); err != nil {
			return fmt.Errorf("mysql: add custom_data column: %w", err)
		}
	}

	// 2. Get existing generated columns (cf_* prefix)
	existingGenCols := make(map[string]bool)
	rows, err := r.db.QueryContext(ctx, `
		SELECT COLUMN_NAME FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'app_user' AND COLUMN_NAME LIKE 'cf_%'
	`)
	if err != nil {
		return fmt.Errorf("mysql: get existing generated columns: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var col string
		if err := rows.Scan(&col); err != nil {
			return err
		}
		existingGenCols[col] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// 3. Apply field changes
	for _, field := range fields {
		fieldName := mysqlIdentifier(field.Name)
		if fieldName == "" || isSystemColumn(fieldName) {
			continue
		}

		genCol := "cf_" + fieldName
		colType := mapFieldTypeToMySQL(field.Type)

		if field.Unique {
			// Unique: generated stored column + UNIQUE index
			if !existingGenCols[genCol] {
				// MySQL generated column syntax
				query := fmt.Sprintf(
					"ALTER TABLE app_user ADD COLUMN %s %s GENERATED ALWAYS AS (JSON_UNQUOTE(JSON_EXTRACT(custom_data, '$.%s'))) STORED",
					genCol, colType, fieldName,
				)
				if _, err := r.db.ExecContext(ctx, query); err != nil {
					return fmt.Errorf("mysql: add generated column %s: %w", genCol, err)
				}
			}

			uqName := fmt.Sprintf("uq_cf_%s", fieldName)
			query := fmt.Sprintf("CREATE UNIQUE INDEX %s ON app_user (%s)", uqName, genCol)
			_, err := r.db.ExecContext(ctx, query)
			if err != nil && !isDuplicateKeyError(err) {
				// Index may already exist — log and continue
				log.Printf("Tenant %s: Failed to add unique index %s: %v", tenantID, uqName, err)
			}

			// Drop expression index if field changed from indexed to unique
			idxName := fmt.Sprintf("idx_cf_%s", fieldName)
			_, _ = r.db.ExecContext(ctx, fmt.Sprintf("DROP INDEX %s ON app_user", idxName))

		} else if field.Indexed {
			// Indexed (non-unique): expression index on JSON extract
			idxName := fmt.Sprintf("idx_cf_%s", fieldName)
			// MySQL 8.0+ supports functional indexes on expressions
			query := fmt.Sprintf(
				"CREATE INDEX %s ON app_user ((CAST(custom_data->>'$.%s' AS CHAR(255))))",
				idxName, fieldName,
			)
			_, err := r.db.ExecContext(ctx, query)
			if err != nil && !isDuplicateKeyError(err) {
				log.Printf("Tenant %s: Failed to create index %s: %v", tenantID, idxName, err)
			}

			// Drop unique index + generated column if field changed from unique to indexed
			uqName := fmt.Sprintf("uq_cf_%s", fieldName)
			_, _ = r.db.ExecContext(ctx, fmt.Sprintf("DROP INDEX %s ON app_user", uqName))
			if existingGenCols[genCol] {
				_, _ = r.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE app_user DROP COLUMN %s", genCol))
			}
		} else {
			// Plain field — clean up
			idxName := fmt.Sprintf("idx_cf_%s", fieldName)
			_, _ = r.db.ExecContext(ctx, fmt.Sprintf("DROP INDEX %s ON app_user", idxName))
			uqName := fmt.Sprintf("uq_cf_%s", fieldName)
			_, _ = r.db.ExecContext(ctx, fmt.Sprintf("DROP INDEX %s ON app_user", uqName))
			if existingGenCols[genCol] {
				_, _ = r.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE app_user DROP COLUMN %s", genCol))
			}
		}
	}

	// 4. Drop generated columns for fields removed from definition
	allValidGenCols := make(map[string]bool)
	for _, field := range fields {
		fieldName := mysqlIdentifier(field.Name)
		if fieldName != "" {
			allValidGenCols["cf_"+fieldName] = true
		}
	}
	for col := range existingGenCols {
		if !allValidGenCols[col] {
			fieldName := col[3:] // strip "cf_" prefix
			uqName := fmt.Sprintf("uq_cf_%s", fieldName)
			_, _ = r.db.ExecContext(ctx, fmt.Sprintf("DROP INDEX %s ON app_user", uqName))
			idxName := fmt.Sprintf("idx_cf_%s", fieldName)
			_, _ = r.db.ExecContext(ctx, fmt.Sprintf("DROP INDEX %s ON app_user", idxName))
			if _, err := r.db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE app_user DROP COLUMN %s", col)); err != nil {
				return fmt.Errorf("mysql: drop generated column %s: %w", col, err)
			}
		}
	}

	return nil
}

// isDuplicateKeyError checks if a MySQL error is a duplicate key/index error.
func isDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "Duplicate") || strings.Contains(msg, "already exists")
}

func mapFieldTypeToMySQL(fieldType string) string {
	switch fieldType {
	case "string", "text":
		return "VARCHAR(255)"
	case "number", "integer":
		return "INT"
	case "float", "decimal":
		return "DECIMAL(10,2)"
	case "boolean", "bool":
		return "TINYINT(1)"
	case "date":
		return "DATE"
	case "datetime", "timestamp":
		return "DATETIME(6)"
	case "json", "object", "array":
		return "JSON"
	default:
		return "TEXT"
	}
}

func (r *schemaRepo) EnsureIndexes(ctx context.Context, tenantID string, schemaDef map[string]any) error {
	// Por simplicidad, no implementamos índices dinámicos en la primera versión
	// Los índices esenciales se crean en las migraciones
	return nil
}

func (r *schemaRepo) IntrospectColumns(ctx context.Context, tenantID, tableName string) ([]repository.ColumnInfo, error) {
	const query = `
		SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT
		FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?
		ORDER BY ORDINAL_POSITION
	`
	rows, err := r.db.QueryContext(ctx, query, tableName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var columns []repository.ColumnInfo
	for rows.Next() {
		var col repository.ColumnInfo
		var nullable string
		var defaultVal sql.NullString
		if err := rows.Scan(&col.Name, &col.DataType, &nullable, &defaultVal); err != nil {
			return nil, err
		}
		col.IsNullable = nullable == "YES"
		if defaultVal.Valid {
			col.Default = defaultVal.String
		}
		columns = append(columns, col)
	}
	return columns, rows.Err()
}
