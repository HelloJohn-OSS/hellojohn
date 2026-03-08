// internal/store/adapters/pg/cp_tenant_repo.go
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// cpTenantRepo implementa repository.TenantRepository sobre la Global DB (cp_tenant).
type cpTenantRepo struct {
	pool *pgxpool.Pool
}

func (r *cpTenantRepo) GetBySlug(ctx context.Context, slug string) (*repository.Tenant, error) {
	const q = `
		SELECT id, slug, name, language, settings, enabled, created_at, updated_at
		FROM cp_tenant WHERE slug = $1`
	t, err := r.scanOne(ctx, q, slug)
	if err != nil {
		return nil, fmt.Errorf("cp_tenant_repo: get by slug: %w", err)
	}
	return t, nil
}

func (r *cpTenantRepo) GetByID(ctx context.Context, id string) (*repository.Tenant, error) {
	const q = `
		SELECT id, slug, name, language, settings, enabled, created_at, updated_at
		FROM cp_tenant WHERE id = $1`
	t, err := r.scanOne(ctx, q, id)
	if err != nil {
		return nil, fmt.Errorf("cp_tenant_repo: get by id: %w", err)
	}
	return t, nil
}

func (r *cpTenantRepo) List(ctx context.Context) ([]repository.Tenant, error) {
	const q = `
		SELECT id, slug, name, language, settings, enabled, created_at, updated_at
		FROM cp_tenant ORDER BY slug`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("cp_tenant_repo: list: %w", err)
	}
	defer rows.Close()

	var out []repository.Tenant
	for rows.Next() {
		t, err := r.scanRow(rows)
		if err != nil {
			return nil, fmt.Errorf("cp_tenant_repo: scan row: %w", err)
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func (r *cpTenantRepo) Create(ctx context.Context, tenant *repository.Tenant) error {
	settingsJSON, err := json.Marshal(tenant.Settings)
	if err != nil {
		return fmt.Errorf("cp_tenant_repo: marshal settings: %w", err)
	}
	// Enabled no existe en repository.Tenant — todos los creados por este path están habilitados
	const q = `
		INSERT INTO cp_tenant (id, slug, name, language, settings, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, true, now(), now())
		ON CONFLICT (slug) DO UPDATE
		  SET name=$3, language=$4, settings=$5, updated_at=now()`
	_, err = r.pool.Exec(ctx, q,
		tenant.ID, tenant.Slug, tenant.Name, tenant.Language, string(settingsJSON))
	if err != nil {
		return fmt.Errorf("cp_tenant_repo: create: %w", err)
	}
	return nil
}

func (r *cpTenantRepo) Update(ctx context.Context, tenant *repository.Tenant) error {
	settingsJSON, err := json.Marshal(tenant.Settings)
	if err != nil {
		return fmt.Errorf("cp_tenant_repo: marshal settings: %w", err)
	}
	const q = `
		UPDATE cp_tenant
		SET name=$1, language=$2, settings=$3, updated_at=now()
		WHERE slug=$4`
	tag, err := r.pool.Exec(ctx, q, tenant.Name, tenant.Language, string(settingsJSON), tenant.Slug)
	if err != nil {
		return fmt.Errorf("cp_tenant_repo: update: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *cpTenantRepo) Delete(ctx context.Context, slug string) error {
	const q = `DELETE FROM cp_tenant WHERE slug = $1`
	tag, err := r.pool.Exec(ctx, q, slug)
	if err != nil {
		return fmt.Errorf("cp_tenant_repo: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *cpTenantRepo) UpdateSettings(ctx context.Context, slug string, settings *repository.TenantSettings) error {
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("cp_tenant_repo: marshal settings: %w", err)
	}
	const q = `UPDATE cp_tenant SET settings=$1, updated_at=now() WHERE slug=$2`
	tag, err := r.pool.Exec(ctx, q, string(settingsJSON), slug)
	if err != nil {
		return fmt.Errorf("cp_tenant_repo: update settings: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

// ─── Helpers internos ───

func (r *cpTenantRepo) scanOne(ctx context.Context, q string, args ...any) (*repository.Tenant, error) {
	row := r.pool.QueryRow(ctx, q, args...)
	t, err := r.scanRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	return t, err
}

func (r *cpTenantRepo) scanRow(row interface {
	Scan(dest ...any) error
}) (*repository.Tenant, error) {
	var t repository.Tenant
	var settingsJSON []byte
	var enabled bool
	err := row.Scan(
		&t.ID, &t.Slug, &t.Name, &t.Language,
		&settingsJSON, &enabled, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	if len(settingsJSON) > 0 {
		_ = json.Unmarshal(settingsJSON, &t.Settings)
	}
	return &t, nil
}

// isPgUniqueViolation detecta violaciones de UNIQUE constraint (código 23505).
func isPgUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// Verificación en compilación: cpTenantRepo debe satisfacer TenantRepository.
var _ repository.TenantRepository = (*cpTenantRepo)(nil)
