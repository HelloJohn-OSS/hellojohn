package pg

import (
	"context"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Compile-time interface check.
var _ repository.WebAuthnRepository = (*webAuthnRepo)(nil)

type webAuthnRepo struct {
	pool *pgxpool.Pool
}

func (r *webAuthnRepo) Create(ctx context.Context, tenantID string, cred repository.WebAuthnCredential) error {
	const q = `
		INSERT INTO webauthn_credential
			(tenant_id, user_id, credential_id, public_key, aaguid, sign_count,
			 transports, user_verified, backup_eligible, backup_state, name)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err := r.pool.Exec(ctx, q,
		tenantID,
		cred.UserID,
		cred.CredentialID,
		cred.PublicKey,
		cred.AAGUID,
		int64(cred.SignCount),
		cred.Transports,
		cred.UserVerified,
		cred.BackupEligible,
		cred.BackupState,
		cred.Name,
	)
	return err
}

func (r *webAuthnRepo) GetByUserID(ctx context.Context, tenantID, userID string) ([]repository.WebAuthnCredential, error) {
	const q = `
		SELECT id, tenant_id, user_id, credential_id, public_key, aaguid, sign_count,
		       transports, user_verified, backup_eligible, backup_state, name,
		       created_at, last_used_at
		FROM webauthn_credential
		WHERE tenant_id = $1 AND user_id = $2
		ORDER BY created_at ASC
	`

	rows, err := r.pool.Query(ctx, q, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]repository.WebAuthnCredential, 0)
	for rows.Next() {
		item, err := scanWebAuthnCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *webAuthnRepo) GetByCredentialID(ctx context.Context, tenantID string, credID []byte) (*repository.WebAuthnCredential, error) {
	const q = `
		SELECT id, tenant_id, user_id, credential_id, public_key, aaguid, sign_count,
		       transports, user_verified, backup_eligible, backup_state, name,
		       created_at, last_used_at
		FROM webauthn_credential
		WHERE tenant_id = $1 AND credential_id = $2
	`

	rows, err := r.pool.Query(ctx, q, tenantID, credID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, nil
	}
	item, err := scanWebAuthnCredential(rows)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *webAuthnRepo) UpdateSignCount(ctx context.Context, tenantID string, credID []byte, newCount uint32) error {
	const q = `
		UPDATE webauthn_credential
		SET sign_count = $3
		WHERE tenant_id = $1 AND credential_id = $2
	`
	_, err := r.pool.Exec(ctx, q, tenantID, credID, int64(newCount))
	return err
}

func (r *webAuthnRepo) UpdateLastUsed(ctx context.Context, tenantID string, credID []byte) error {
	const q = `
		UPDATE webauthn_credential
		SET last_used_at = now()
		WHERE tenant_id = $1 AND credential_id = $2
	`
	_, err := r.pool.Exec(ctx, q, tenantID, credID)
	return err
}

func (r *webAuthnRepo) Delete(ctx context.Context, tenantID, id string) error {
	const q = `DELETE FROM webauthn_credential WHERE tenant_id = $1 AND id = $2`
	_, err := r.pool.Exec(ctx, q, tenantID, id)
	return err
}

func scanWebAuthnCredential(row pgx.Row) (repository.WebAuthnCredential, error) {
	var (
		item      repository.WebAuthnCredential
		signCount int64
		lastUsed  *time.Time
	)
	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.UserID,
		&item.CredentialID,
		&item.PublicKey,
		&item.AAGUID,
		&signCount,
		&item.Transports,
		&item.UserVerified,
		&item.BackupEligible,
		&item.BackupState,
		&item.Name,
		&item.CreatedAt,
		&lastUsed,
	)
	if err != nil {
		return repository.WebAuthnCredential{}, err
	}
	item.SignCount = uint32(signCount)
	item.LastUsedAt = lastUsed
	return item, nil
}
