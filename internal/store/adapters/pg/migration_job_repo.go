package pg

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

type pgMigrationJobRepo struct{ pool *pgxpool.Pool }

// NewMigrationJobRepo crea un adaptador PG para MigrationJobRepository.
func NewMigrationJobRepo(pool *pgxpool.Pool) repository.MigrationJobRepository {
	return &pgMigrationJobRepo{pool: pool}
}

// compile-time check
var _ repository.MigrationJobRepository = (*pgMigrationJobRepo)(nil)

func (r *pgMigrationJobRepo) Create(ctx context.Context, job repository.MigrationJob) error {
	const q = `
		INSERT INTO migration_jobs (id, tenant_id, type, status, progress_pct, source_info, target_info, started_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
	`
	_, err := r.pool.Exec(ctx, q, job.ID, job.TenantID, job.Type, job.Status,
		job.ProgressPct, job.SourceInfo, job.TargetInfo, job.StartedAt)
	return err
}

func (r *pgMigrationJobRepo) GetByID(ctx context.Context, id string) (*repository.MigrationJob, error) {
	const q = `
		SELECT id, tenant_id, type, status, progress_pct, COALESCE(source_info,''),
		       COALESCE(target_info,''), COALESCE(error,''), started_at, completed_at, created_at
		FROM migration_jobs WHERE id = $1
	`
	var j repository.MigrationJob
	err := r.pool.QueryRow(ctx, q, id).Scan(
		&j.ID, &j.TenantID, &j.Type, &j.Status, &j.ProgressPct,
		&j.SourceInfo, &j.TargetInfo, &j.Error, &j.StartedAt, &j.CompletedAt, &j.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	return &j, err
}

func (r *pgMigrationJobRepo) ListByTenant(ctx context.Context, tenantID string) ([]repository.MigrationJob, error) {
	const q = `
		SELECT id, tenant_id, type, status, progress_pct, COALESCE(source_info,''),
		       COALESCE(target_info,''), COALESCE(error,''), started_at, completed_at, created_at
		FROM migration_jobs WHERE tenant_id = $1 ORDER BY created_at DESC
	`
	rows, err := r.pool.Query(ctx, q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []repository.MigrationJob
	for rows.Next() {
		var j repository.MigrationJob
		if err := rows.Scan(&j.ID, &j.TenantID, &j.Type, &j.Status, &j.ProgressPct,
			&j.SourceInfo, &j.TargetInfo, &j.Error, &j.StartedAt, &j.CompletedAt, &j.CreatedAt); err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

func (r *pgMigrationJobRepo) UpdateProgress(ctx context.Context, id string, pct int) error {
	_, err := r.pool.Exec(ctx, `UPDATE migration_jobs SET progress_pct=$2 WHERE id=$1`, id, pct)
	return err
}

func (r *pgMigrationJobRepo) Complete(ctx context.Context, id string) error {
	now := time.Now()
	_, err := r.pool.Exec(ctx,
		`UPDATE migration_jobs SET status='completed', progress_pct=100, completed_at=$2 WHERE id=$1`,
		id, now)
	return err
}

func (r *pgMigrationJobRepo) Fail(ctx context.Context, id, errMsg string) error {
	now := time.Now()
	_, err := r.pool.Exec(ctx,
		`UPDATE migration_jobs SET status='failed', error=$2, completed_at=$3 WHERE id=$1`,
		id, errMsg, now)
	return err
}
