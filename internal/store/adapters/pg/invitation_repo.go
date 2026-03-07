package pg

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

var _ repository.InvitationRepository = (*invitationRepo)(nil)

type invitationRepo struct {
	pool *pgxpool.Pool
}

func (r *invitationRepo) Create(ctx context.Context, in repository.CreateInvitationInput) (*repository.Invitation, error) {
	const q = `
		INSERT INTO user_invitation
			(tenant_id, email, token_hash, invited_by, roles, expires_at)
		VALUES
			($1, $2, $3, $4, $5, $6)
		RETURNING id, tenant_id, email, token_hash, status, invited_by, roles,
		          expires_at, accepted_at, created_at, updated_at
	`

	var out repository.Invitation
	if err := r.pool.QueryRow(ctx, q,
		in.TenantID,
		in.Email,
		in.TokenHash,
		in.InvitedByID,
		in.Roles,
		in.ExpiresAt,
	).Scan(
		&out.ID,
		&out.TenantID,
		&out.Email,
		&out.TokenHash,
		&out.Status,
		&out.InvitedByID,
		&out.Roles,
		&out.ExpiresAt,
		&out.AcceptedAt,
		&out.CreatedAt,
		&out.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *invitationRepo) GetByTokenHash(ctx context.Context, tenantID, hash string) (*repository.Invitation, error) {
	const q = `
		SELECT id, tenant_id, email, token_hash, status, invited_by, roles,
		       expires_at, accepted_at, created_at, updated_at
		FROM user_invitation
		WHERE tenant_id = $1 AND token_hash = $2
	`

	var out repository.Invitation
	err := r.pool.QueryRow(ctx, q, tenantID, hash).Scan(
		&out.ID,
		&out.TenantID,
		&out.Email,
		&out.TokenHash,
		&out.Status,
		&out.InvitedByID,
		&out.Roles,
		&out.ExpiresAt,
		&out.AcceptedAt,
		&out.CreatedAt,
		&out.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *invitationRepo) GetByID(ctx context.Context, tenantID, id string) (*repository.Invitation, error) {
	const q = `
		SELECT id, tenant_id, email, token_hash, status, invited_by, roles,
		       expires_at, accepted_at, created_at, updated_at
		FROM user_invitation
		WHERE tenant_id = $1 AND id = $2
	`

	var out repository.Invitation
	err := r.pool.QueryRow(ctx, q, tenantID, id).Scan(
		&out.ID,
		&out.TenantID,
		&out.Email,
		&out.TokenHash,
		&out.Status,
		&out.InvitedByID,
		&out.Roles,
		&out.ExpiresAt,
		&out.AcceptedAt,
		&out.CreatedAt,
		&out.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *invitationRepo) List(ctx context.Context, tenantID string, status *repository.InvitationStatus, limit, offset int) ([]repository.Invitation, error) {
	q := `
		SELECT id, tenant_id, email, token_hash, status, invited_by, roles,
		       expires_at, accepted_at, created_at, updated_at
		FROM user_invitation
		WHERE tenant_id = $1
	`

	args := []any{tenantID}
	argPos := 2

	if status != nil {
		q += fmt.Sprintf(" AND status = $%d", argPos)
		args = append(args, string(*status))
		argPos++
	}

	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argPos, argPos+1)
	args = append(args, limit, offset)

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]repository.Invitation, 0, limit)
	for rows.Next() {
		var item repository.Invitation
		if err := rows.Scan(
			&item.ID,
			&item.TenantID,
			&item.Email,
			&item.TokenHash,
			&item.Status,
			&item.InvitedByID,
			&item.Roles,
			&item.ExpiresAt,
			&item.AcceptedAt,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, item)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *invitationRepo) UpdateStatus(ctx context.Context, tenantID, id string, newStatus repository.InvitationStatus, acceptedAt *time.Time) error {
	const q = `
		UPDATE user_invitation
		SET status = $3, accepted_at = $4, updated_at = now()
		WHERE tenant_id = $1 AND id = $2 AND status = 'pending'
	`

	tag, err := r.pool.Exec(ctx, q, tenantID, id, string(newStatus), acceptedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrInvitationNotPending
	}
	return nil
}

func (r *invitationRepo) Delete(ctx context.Context, tenantID, id string) error {
	const q = `DELETE FROM user_invitation WHERE tenant_id = $1 AND id = $2`
	_, err := r.pool.Exec(ctx, q, tenantID, id)
	return err
}
