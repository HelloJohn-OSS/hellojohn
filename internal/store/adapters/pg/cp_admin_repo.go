// internal/store/adapters/pg/cp_admin_repo.go
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// cpAdminRepo implementa repository.AdminRepository sobre cp_admin.
type cpAdminRepo struct {
	pool *pgxpool.Pool
}

func (r *cpAdminRepo) List(ctx context.Context, filter repository.AdminFilter) ([]repository.Admin, error) {
	q := `
		SELECT id, email, name, role, tenant_ids, enabled, last_seen_at, disabled_at,
		       email_verified, COALESCE(social_provider,''), COALESCE(plan,'free'),
		       COALESCE(onboarding_completed, false),
		       created_at, updated_at
		FROM cp_admin WHERE 1=1`
	args := []any{}
	n := 1

	if filter.Disabled != nil {
		if *filter.Disabled {
			q += fmt.Sprintf(" AND disabled_at IS NOT NULL")
		} else {
			q += fmt.Sprintf(" AND disabled_at IS NULL")
		}
	}
	q += " ORDER BY email"
	if filter.Limit > 0 {
		q += fmt.Sprintf(" LIMIT $%d", n)
		args = append(args, filter.Limit)
		n++
	}
	if filter.Offset > 0 {
		q += fmt.Sprintf(" OFFSET $%d", n)
		args = append(args, filter.Offset)
	}

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("cp_admin_repo: list: %w", err)
	}
	defer rows.Close()

	var out []repository.Admin
	for rows.Next() {
		a, err := r.scanRow(rows)
		if err != nil {
			return nil, fmt.Errorf("cp_admin_repo: scan: %w", err)
		}
		// Filtrar por Type si está especificado
		if filter.Type != nil && a.Type != *filter.Type {
			continue
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (r *cpAdminRepo) GetByID(ctx context.Context, id string) (*repository.Admin, error) {
	const q = `
		SELECT id, email, name, role, tenant_ids, enabled, last_seen_at, disabled_at,
		       email_verified, COALESCE(social_provider,''), COALESCE(plan,'free'),
		       COALESCE(onboarding_completed, false),
		       created_at, updated_at
		FROM cp_admin WHERE id = $1`
	row := r.pool.QueryRow(ctx, q, id)
	a, err := r.scanRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cp_admin_repo: get by id: %w", err)
	}
	return a, nil
}

func (r *cpAdminRepo) GetByEmail(ctx context.Context, email string) (*repository.Admin, error) {
	const q = `
		SELECT id, email, name, role, tenant_ids, enabled, last_seen_at, disabled_at,
		       email_verified, COALESCE(social_provider,''), COALESCE(plan,'free'),
		       COALESCE(onboarding_completed, false),
		       created_at, updated_at
		FROM cp_admin WHERE email = $1`
	row := r.pool.QueryRow(ctx, q, email)
	a, err := r.scanRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cp_admin_repo: get by email: %w", err)
	}
	return a, nil
}

func (r *cpAdminRepo) Create(ctx context.Context, input repository.CreateAdminInput) (*repository.Admin, error) {
	tenantSlugs := make([]string, len(input.TenantAccess))
	for i, e := range input.TenantAccess {
		tenantSlugs[i] = e.TenantSlug
	}
	adminType := string(input.Type)
	if adminType == "" {
		adminType = string(repository.AdminTypeGlobal)
	}
	const q = `
		INSERT INTO cp_admin
			(email, password_hash, name, role, tenant_ids, email_verified, social_provider, plan, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, now(), now())
		ON CONFLICT (email) DO NOTHING
		RETURNING id, email, name, role, tenant_ids, enabled, last_seen_at, disabled_at,
		          email_verified, COALESCE(social_provider,''), COALESCE(plan,'free'),
		          COALESCE(onboarding_completed, false),
		          created_at, updated_at`
	planValue := input.Plan
	if planValue == "" {
		planValue = "free"
	}
	row := r.pool.QueryRow(ctx, q,
		input.Email, input.PasswordHash, input.Name, adminType, tenantSlugs,
		input.EmailVerified, input.SocialProvider, planValue)
	a, err := r.scanRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrConflict
	}
	if err != nil {
		if isPgUniqueViolation(err) {
			return nil, repository.ErrConflict
		}
		return nil, fmt.Errorf("cp_admin_repo: create: %w", err)
	}
	return a, nil
}

func (r *cpAdminRepo) Update(ctx context.Context, id string, input repository.UpdateAdminInput) (*repository.Admin, error) {
	// Construir UPDATE dinámico con campos opcionales
	setClauses := []string{}
	args := []any{id}
	n := 2
	if input.Email != nil {
		setClauses = append(setClauses, fmt.Sprintf("email=$%d", n))
		args = append(args, *input.Email)
		n++
	}
	if input.PasswordHash != nil {
		setClauses = append(setClauses, fmt.Sprintf("password_hash=$%d", n))
		args = append(args, *input.PasswordHash)
		n++
	}
	if input.Name != nil {
		setClauses = append(setClauses, fmt.Sprintf("name=$%d", n))
		args = append(args, *input.Name)
		n++
	}
	if input.TenantAccess != nil {
		slugs := make([]string, len(*input.TenantAccess))
		for i, e := range *input.TenantAccess {
			slugs[i] = e.TenantSlug
		}
		setClauses = append(setClauses, fmt.Sprintf("tenant_ids=$%d", n))
		args = append(args, slugs)
		n++
	}
	if input.DisabledAt != nil {
		setClauses = append(setClauses, fmt.Sprintf("disabled_at=$%d", n))
		args = append(args, *input.DisabledAt)
		n++
	}

	if len(setClauses) == 0 {
		return r.GetByID(ctx, id)
	}

	setClauses = append(setClauses, "updated_at=now()")
	q := fmt.Sprintf(`
		UPDATE cp_admin SET %s WHERE id=$1
		RETURNING id, email, name, role, tenant_ids, enabled, last_seen_at, disabled_at,
		          email_verified, COALESCE(social_provider,''), COALESCE(plan,'free'),
		          COALESCE(onboarding_completed, false),
		          created_at, updated_at`,
		joinClauses(setClauses))
	row := r.pool.QueryRow(ctx, q, args...)
	a, err := r.scanRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cp_admin_repo: update: %w", err)
	}
	return a, nil
}

func (r *cpAdminRepo) Delete(ctx context.Context, id string) error {
	const q = `DELETE FROM cp_admin WHERE id = $1`
	tag, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("cp_admin_repo: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *cpAdminRepo) CheckPassword(passwordHash, plainPassword string) bool {
	return bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(plainPassword)) == nil
}

func (r *cpAdminRepo) UpdateLastSeen(ctx context.Context, id string) error {
	const q = `UPDATE cp_admin SET last_seen_at=now() WHERE id=$1`
	_, err := r.pool.Exec(ctx, q, id)
	return err
}

func (r *cpAdminRepo) AssignTenants(ctx context.Context, adminID string, tenantIDs []string) error {
	if tenantIDs == nil {
		tenantIDs = []string{}
	}
	const q = `UPDATE cp_admin SET tenant_ids=$1, updated_at=now() WHERE id=$2`
	tag, err := r.pool.Exec(ctx, q, tenantIDs, adminID)
	if err != nil {
		return fmt.Errorf("cp_admin_repo: assign tenants: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *cpAdminRepo) HasAccessToTenant(ctx context.Context, adminID, tenantID string) (bool, error) {
	// Los admins globales (role='global') siempre tienen acceso
	const qGlobal = `SELECT role FROM cp_admin WHERE id=$1 AND enabled=true AND disabled_at IS NULL`
	var role string
	if err := r.pool.QueryRow(ctx, qGlobal, adminID).Scan(&role); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if role == string(repository.AdminTypeGlobal) {
		return true, nil
	}
	const qTenant = `SELECT 1 FROM cp_admin WHERE id=$1 AND $2=ANY(tenant_ids) AND enabled=true AND disabled_at IS NULL`
	var dummy int
	err := r.pool.QueryRow(ctx, qTenant, adminID, tenantID).Scan(&dummy)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// SetInviteToken implementa AdminRepository.SetInviteToken
func (r *cpAdminRepo) SetInviteToken(ctx context.Context, id, tokenHash string, expiresAt time.Time) error {
	const q = `UPDATE cp_admin SET invite_token_hash=$1, invite_expires_at=$2, status='pending', updated_at=now() WHERE id=$3`
	tag, err := r.pool.Exec(ctx, q, tokenHash, expiresAt, id)
	if err != nil {
		return fmt.Errorf("cp_admin_repo: set invite token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

// GetByInviteTokenHash implementa AdminRepository.GetByInviteTokenHash
func (r *cpAdminRepo) GetByInviteTokenHash(ctx context.Context, tokenHash string) (*repository.Admin, error) {
	const q = `SELECT id, email, name, role, tenant_ids, enabled, last_seen_at, disabled_at,
	       email_verified, COALESCE(social_provider,''), COALESCE(plan,'free'),
	       COALESCE(onboarding_completed, false),
	       created_at, updated_at FROM cp_admin WHERE invite_token_hash=$1 AND status='pending'`
	row := r.pool.QueryRow(ctx, q, tokenHash)
	admin, err := r.scanRow(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("cp_admin_repo: get by invite token: %w", err)
	}
	return admin, nil
}

// ActivateWithPassword implementa AdminRepository.ActivateWithPassword
func (r *cpAdminRepo) ActivateWithPassword(ctx context.Context, id, passwordHash string) error {
	const q = `UPDATE cp_admin SET password_hash=$1, status='active', invite_token_hash=NULL, invite_expires_at=NULL, updated_at=now() WHERE id=$2`
	tag, err := r.pool.Exec(ctx, q, passwordHash, id)
	if err != nil {
		return fmt.Errorf("cp_admin_repo: activate with password: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

// scanRow escanea un Admin desde la DB.
// La columna `role` se mapea a `Type AdminType`.
// La columna `enabled` determina si el admin está activo (junto a `disabled_at`).
func (r *cpAdminRepo) scanRow(row interface {
	Scan(dest ...any) error
}) (*repository.Admin, error) {
	var a repository.Admin
	var role string
	var tenantIDsJSON []byte
	var enabled bool
	var lastSeenAt *time.Time
	var disabledAt *time.Time

	err := row.Scan(
		&a.ID, &a.Email, &a.Name, &role,
		&tenantIDsJSON, &enabled, &lastSeenAt, &disabledAt,
		&a.EmailVerified, &a.SocialProvider, &a.Plan,
		&a.OnboardingCompleted,
		&a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	a.Type = repository.AdminType(role)
	a.LastSeenAt = lastSeenAt
	a.DisabledAt = disabledAt

	// tenant_ids es TEXT[] en PG — pgx lo escanea como []byte en algunos contextos
	// Intentar como []string directo (pgx convierte TEXT[] automáticamente)
	// Si la columna llega como []byte por algún driver quirk, deserializar:
	if len(tenantIDsJSON) > 0 && tenantIDsJSON[0] == '[' {
		var slugs []string
		_ = json.Unmarshal(tenantIDsJSON, &slugs)
		a.AssignedTenants = slugs
		a.TenantAccess = make([]repository.TenantAccessEntry, len(slugs))
		for i, s := range slugs {
			a.TenantAccess[i] = repository.TenantAccessEntry{TenantSlug: s, Role: "owner"}
		}
	}
	return &a, nil
}

func (r *cpAdminRepo) CreateEmailVerification(ctx context.Context, v repository.AdminEmailVerification) error {
	const q = `
		INSERT INTO admin_email_verification (id, admin_id, token_hash, expires_at, created_at)
		VALUES (gen_random_uuid(), $1, $2, $3, now())`
	_, err := r.pool.Exec(ctx, q, v.AdminID, v.TokenHash, v.ExpiresAt)
	return err
}

func (r *cpAdminRepo) GetEmailVerificationByHash(ctx context.Context, hash string) (*repository.AdminEmailVerification, error) {
	const q = `
		SELECT id, admin_id, token_hash, expires_at, used_at, created_at
		FROM admin_email_verification WHERE token_hash = $1`
	var v repository.AdminEmailVerification
	err := r.pool.QueryRow(ctx, q, hash).Scan(
		&v.ID, &v.AdminID, &v.TokenHash, &v.ExpiresAt, &v.UsedAt, &v.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	return &v, err
}

func (r *cpAdminRepo) MarkEmailVerificationUsed(ctx context.Context, id string) error {
	const q = `UPDATE admin_email_verification SET used_at=now() WHERE id=$1`
	_, err := r.pool.Exec(ctx, q, id)
	return err
}

func (r *cpAdminRepo) UpdateEmailVerified(ctx context.Context, adminID string, verified bool) error {
	status := "active"
	if !verified {
		status = "pending_verification"
	}
	const q = `UPDATE cp_admin SET email_verified=$1, status=$2, updated_at=now() WHERE id=$3`
	tag, err := r.pool.Exec(ctx, q, verified, status, adminID)
	if err != nil {
		return fmt.Errorf("cp_admin_repo: update email verified: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *cpAdminRepo) UpdateSocialProvider(ctx context.Context, adminID, provider, plan string) error {
	const q = `UPDATE cp_admin SET social_provider=$1, plan=$2, updated_at=now() WHERE id=$3`
	_, err := r.pool.Exec(ctx, q, provider, plan, adminID)
	return err
}

// UpdatePlan actualiza el campo plan del admin.
func (r *cpAdminRepo) UpdatePlan(ctx context.Context, adminID, plan string) error {
	const q = `UPDATE cp_admin SET plan=$1, updated_at=now() WHERE id=$2`
	tag, err := r.pool.Exec(ctx, q, plan, adminID)
	if err != nil {
		return fmt.Errorf("cp_admin_repo: update plan: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

// CountTenantsByAdmin cuenta los tenants asignados al admin en cp_admin_tenant_access.
// Stub: retorna 0 hasta migrar la tabla de accesos a PG.
func (r *cpAdminRepo) CountTenantsByAdmin(_ context.Context, _ string) (int, error) {
	return 0, nil
}

// CountAdminsByOwner cuenta los admins creados por el admin dado.
func (r *cpAdminRepo) CountAdminsByOwner(ctx context.Context, adminID string) (int, error) {
	const q = `SELECT COUNT(*) FROM cp_admin WHERE created_by=$1`
	var count int
	err := r.pool.QueryRow(ctx, q, adminID).Scan(&count)
	if err != nil {
		return 0, nil // fail-open
	}
	return count, nil
}

// GetCurrentMAU retorna el MAU actual. Stub: retorna 0 (fail-open).
func (r *cpAdminRepo) GetCurrentMAU(_ context.Context, _ string) (int, error) {
	return 0, nil
}

// SetOnboardingCompleted marca si el admin completó el wizard de onboarding.
func (r *cpAdminRepo) SetOnboardingCompleted(ctx context.Context, adminID string, completed bool) error {
	const q = `UPDATE cp_admin SET onboarding_completed = $1, updated_at = now() WHERE id = $2`
	tag, err := r.pool.Exec(ctx, q, completed, adminID)
	if err != nil {
		return fmt.Errorf("cp_admin_repo: set onboarding completed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func joinClauses(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += ", "
		}
		result += p
	}
	return result
}

// Verificación en compilación.
var _ repository.AdminRepository = (*cpAdminRepo)(nil)

// ═══════════════════════════════════════════════════════════════════════════════
// cpAdminRefreshTokenRepo implementa repository.AdminRefreshTokenRepository.
// ═══════════════════════════════════════════════════════════════════════════════

type cpAdminRefreshTokenRepo struct {
	pool *pgxpool.Pool
}

func (r *cpAdminRefreshTokenRepo) GetByTokenHash(ctx context.Context, tokenHash string) (*repository.AdminRefreshToken, error) {
	const q = `SELECT token_hash, admin_id, expires_at, created_at FROM cp_admin_refresh_token WHERE token_hash=$1`
	var t repository.AdminRefreshToken
	err := r.pool.QueryRow(ctx, q, tokenHash).Scan(&t.TokenHash, &t.AdminID, &t.ExpiresAt, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cp_admin_token_repo: get by hash: %w", err)
	}
	return &t, nil
}

func (r *cpAdminRefreshTokenRepo) ListByAdminID(ctx context.Context, adminID string) ([]repository.AdminRefreshToken, error) {
	const q = `SELECT token_hash, admin_id, expires_at, created_at FROM cp_admin_refresh_token WHERE admin_id=$1`
	rows, err := r.pool.Query(ctx, q, adminID)
	if err != nil {
		return nil, fmt.Errorf("cp_admin_token_repo: list: %w", err)
	}
	defer rows.Close()
	var out []repository.AdminRefreshToken
	for rows.Next() {
		var t repository.AdminRefreshToken
		if err := rows.Scan(&t.TokenHash, &t.AdminID, &t.ExpiresAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r *cpAdminRefreshTokenRepo) Create(ctx context.Context, input repository.CreateAdminRefreshTokenInput) error {
	const q = `
		INSERT INTO cp_admin_refresh_token (admin_id, token_hash, expires_at, created_at)
		VALUES ($1, $2, $3, now())`
	_, err := r.pool.Exec(ctx, q, input.AdminID, input.TokenHash, input.ExpiresAt)
	if err != nil {
		if isPgUniqueViolation(err) {
			return repository.ErrConflict
		}
		return fmt.Errorf("cp_admin_token_repo: create: %w", err)
	}
	return nil
}

func (r *cpAdminRefreshTokenRepo) Delete(ctx context.Context, tokenHash string) error {
	const q = `DELETE FROM cp_admin_refresh_token WHERE token_hash = $1`
	tag, err := r.pool.Exec(ctx, q, tokenHash)
	if err != nil {
		return fmt.Errorf("cp_admin_token_repo: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *cpAdminRefreshTokenRepo) DeleteByAdminID(ctx context.Context, adminID string) (int, error) {
	const q = `DELETE FROM cp_admin_refresh_token WHERE admin_id = $1`
	tag, err := r.pool.Exec(ctx, q, adminID)
	if err != nil {
		return 0, fmt.Errorf("cp_admin_token_repo: delete by admin: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (r *cpAdminRefreshTokenRepo) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	const q = `DELETE FROM cp_admin_refresh_token WHERE expires_at < $1`
	tag, err := r.pool.Exec(ctx, q, now)
	if err != nil {
		return 0, fmt.Errorf("cp_admin_token_repo: delete expired: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// Verificación en compilación.
var _ repository.AdminRefreshTokenRepository = (*cpAdminRefreshTokenRepo)(nil)
