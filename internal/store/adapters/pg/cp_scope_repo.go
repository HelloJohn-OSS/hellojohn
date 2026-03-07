// internal/store/adapters/pg/cp_scope_repo.go
package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// cpScopeRepo implementa repository.ScopeRepository sobre cp_scope.
// El tenantID (UUID) se inyecta al construir el repo.
type cpScopeRepo struct {
	pool     *pgxpool.Pool
	tenantID string
}

func (r *cpScopeRepo) Create(ctx context.Context, input repository.ScopeInput) (*repository.Scope, error) {
	claims := input.Claims
	if claims == nil {
		claims = []string{}
	}
	const q = `
		INSERT INTO cp_scope (tenant_id, name, description, claims, system, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, now(), now())
		ON CONFLICT (tenant_id, name) DO NOTHING
		RETURNING id, tenant_id, name, description, claims, system, created_at, updated_at`
	row := r.pool.QueryRow(ctx, q,
		r.tenantID, input.Name, input.Description, claims, input.System)
	s, err := r.scanRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		// ON CONFLICT DO NOTHING → ya existe
		return nil, repository.ErrConflict
	}
	if err != nil {
		return nil, fmt.Errorf("cp_scope_repo: create: %w", err)
	}
	return s, nil
}

func (r *cpScopeRepo) GetByName(ctx context.Context, name string) (*repository.Scope, error) {
	const q = `
		SELECT id, tenant_id, name, description, claims, system, created_at, updated_at
		FROM cp_scope WHERE tenant_id = $1 AND name = $2`
	row := r.pool.QueryRow(ctx, q, r.tenantID, name)
	s, err := r.scanRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cp_scope_repo: get by name: %w", err)
	}
	return s, nil
}

func (r *cpScopeRepo) List(ctx context.Context) ([]repository.Scope, error) {
	const q = `
		SELECT id, tenant_id, name, description, claims, system, created_at, updated_at
		FROM cp_scope WHERE tenant_id = $1 ORDER BY name`
	rows, err := r.pool.Query(ctx, q, r.tenantID)
	if err != nil {
		return nil, fmt.Errorf("cp_scope_repo: list: %w", err)
	}
	defer rows.Close()

	var out []repository.Scope
	for rows.Next() {
		s, err := r.scanRow(rows)
		if err != nil {
			return nil, fmt.Errorf("cp_scope_repo: scan: %w", err)
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

func (r *cpScopeRepo) Update(ctx context.Context, input repository.ScopeInput) (*repository.Scope, error) {
	claims := input.Claims
	if claims == nil {
		claims = []string{}
	}
	const q = `
		UPDATE cp_scope
		SET description=$3, claims=$4, system=$5, updated_at=now()
		WHERE tenant_id=$1 AND name=$2
		RETURNING id, tenant_id, name, description, claims, system, created_at, updated_at`
	row := r.pool.QueryRow(ctx, q,
		r.tenantID, input.Name, input.Description, claims, input.System)
	s, err := r.scanRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cp_scope_repo: update: %w", err)
	}
	return s, nil
}

func (r *cpScopeRepo) Delete(ctx context.Context, scopeID string) error {
	// scopeID es el nombre del scope (consistente con FS adapter)
	const q = `DELETE FROM cp_scope WHERE tenant_id = $1 AND name = $2`
	tag, err := r.pool.Exec(ctx, q, r.tenantID, scopeID)
	if err != nil {
		return fmt.Errorf("cp_scope_repo: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *cpScopeRepo) Upsert(ctx context.Context, input repository.ScopeInput) (*repository.Scope, error) {
	claims := input.Claims
	if claims == nil {
		claims = []string{}
	}
	const q = `
		INSERT INTO cp_scope (tenant_id, name, description, claims, system, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, now(), now())
		ON CONFLICT (tenant_id, name) DO UPDATE
		  SET description=$3, claims=$4, system=$5, updated_at=now()
		RETURNING id, tenant_id, name, description, claims, system, created_at, updated_at`
	row := r.pool.QueryRow(ctx, q,
		r.tenantID, input.Name, input.Description, claims, input.System)
	s, err := r.scanRow(row)
	if err != nil {
		return nil, fmt.Errorf("cp_scope_repo: upsert: %w", err)
	}
	return s, nil
}

// scanRow escanea un Scope. DisplayName y DependsOn no existen en cp_scope
// (son campos del FS adapter); quedan en cero en el struct.
func (r *cpScopeRepo) scanRow(row interface {
	Scan(dest ...any) error
}) (*repository.Scope, error) {
	var s repository.Scope
	var claims []string
	var updatedAt time.Time
	err := row.Scan(
		&s.ID, &s.TenantID, &s.Name, &s.Description,
		&claims, &s.System, &s.CreatedAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	s.Claims = claims
	s.UpdatedAt = &updatedAt
	return &s, nil
}

// NewScopeRepo construye un cpScopeRepo con tenantID pre-inyectado.
func (c *pgConnection) NewScopeRepo(tenantID string) repository.ScopeRepository {
	return &cpScopeRepo{pool: c.pool, tenantID: tenantID}
}

// Verificación en compilación.
var _ repository.ScopeRepository = (*cpScopeRepo)(nil)
