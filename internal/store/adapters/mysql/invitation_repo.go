package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

var _ repository.InvitationRepository = (*invitationMysqlRepo)(nil)

type invitationMysqlRepo struct {
	db *sql.DB
}

func (r *invitationMysqlRepo) Create(ctx context.Context, in repository.CreateInvitationInput) (*repository.Invitation, error) {
	rolesJSON, err := json.Marshal(in.Roles)
	if err != nil {
		return nil, err
	}

	const q = `
		INSERT INTO user_invitation
			(tenant_id, email, token_hash, invited_by, roles, expires_at)
		VALUES
			(?, ?, ?, ?, ?, ?)
	`
	if _, err := r.db.ExecContext(ctx, q,
		in.TenantID,
		in.Email,
		in.TokenHash,
		in.InvitedByID,
		rolesJSON,
		in.ExpiresAt,
	); err != nil {
		return nil, err
	}

	return r.getByTokenHashInternal(ctx, in.TenantID, in.TokenHash)
}

func (r *invitationMysqlRepo) GetByTokenHash(ctx context.Context, tenantID, hash string) (*repository.Invitation, error) {
	return r.getByTokenHashInternal(ctx, tenantID, hash)
}

func (r *invitationMysqlRepo) getByTokenHashInternal(ctx context.Context, tenantID, hash string) (*repository.Invitation, error) {
	const q = `
		SELECT id, tenant_id, email, token_hash, status, invited_by, roles,
		       expires_at, accepted_at, created_at, updated_at
		FROM user_invitation
		WHERE tenant_id = ? AND token_hash = ?
	`

	return r.scanOne(r.db.QueryRowContext(ctx, q, tenantID, hash))
}

func (r *invitationMysqlRepo) GetByID(ctx context.Context, tenantID, id string) (*repository.Invitation, error) {
	const q = `
		SELECT id, tenant_id, email, token_hash, status, invited_by, roles,
		       expires_at, accepted_at, created_at, updated_at
		FROM user_invitation
		WHERE tenant_id = ? AND id = ?
	`

	return r.scanOne(r.db.QueryRowContext(ctx, q, tenantID, id))
}

func (r *invitationMysqlRepo) scanOne(row *sql.Row) (*repository.Invitation, error) {
	var (
		out      repository.Invitation
		rolesRaw []byte
	)

	err := row.Scan(
		&out.ID,
		&out.TenantID,
		&out.Email,
		&out.TokenHash,
		&out.Status,
		&out.InvitedByID,
		&rolesRaw,
		&out.ExpiresAt,
		&out.AcceptedAt,
		&out.CreatedAt,
		&out.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if len(rolesRaw) > 0 {
		_ = json.Unmarshal(rolesRaw, &out.Roles)
	}
	return &out, nil
}

func (r *invitationMysqlRepo) List(ctx context.Context, tenantID string, status *repository.InvitationStatus, limit, offset int) ([]repository.Invitation, error) {
	q := `
		SELECT id, tenant_id, email, token_hash, status, invited_by, roles,
		       expires_at, accepted_at, created_at, updated_at
		FROM user_invitation
		WHERE tenant_id = ?
	`

	args := []any{tenantID}
	if status != nil {
		q += " AND status = ?"
		args = append(args, string(*status))
	}
	q += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]repository.Invitation, 0, limit)
	for rows.Next() {
		var (
			item     repository.Invitation
			rolesRaw []byte
		)

		if err := rows.Scan(
			&item.ID,
			&item.TenantID,
			&item.Email,
			&item.TokenHash,
			&item.Status,
			&item.InvitedByID,
			&rolesRaw,
			&item.ExpiresAt,
			&item.AcceptedAt,
			&item.CreatedAt,
			&item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if len(rolesRaw) > 0 {
			_ = json.Unmarshal(rolesRaw, &item.Roles)
		}
		out = append(out, item)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r *invitationMysqlRepo) UpdateStatus(ctx context.Context, tenantID, id string, newStatus repository.InvitationStatus, acceptedAt *time.Time) error {
	const q = `
		UPDATE user_invitation
		SET status = ?, accepted_at = ?, updated_at = NOW(6)
		WHERE tenant_id = ? AND id = ? AND status = 'pending'
	`

	res, err := r.db.ExecContext(ctx, q, string(newStatus), acceptedAt, tenantID, id)
	if err != nil {
		return err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return repository.ErrInvitationNotPending
	}
	return nil
}

func (r *invitationMysqlRepo) Delete(ctx context.Context, tenantID, id string) error {
	const q = `DELETE FROM user_invitation WHERE tenant_id = ? AND id = ?`
	_, err := r.db.ExecContext(ctx, q, tenantID, id)
	return err
}
