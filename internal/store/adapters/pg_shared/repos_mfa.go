package pg_shared

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// ─── sharedMFARepo ────────────────────────────────────────────────

// sharedMFARepo implements repository.MFARepository for Global Data Plane.
// GDP schema differences from isolated pg adapter:
//   - Column: secret_enc   (not secret_encrypted)
//   - Column: verified_at  (not confirmed_at)
//   - No updated_at or last_used_at in mfa_totp
//   - Has additional columns: algorithm, digits, period, enabled
type sharedMFARepo struct {
	pool     *pgxpool.Pool
	tenantID uuid.UUID
}

func (r *sharedMFARepo) UpsertTOTP(ctx context.Context, userID, secretEnc string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO mfa_totp (tenant_id, user_id, secret_enc, created_at)
			VALUES ($1, $2, $3, NOW())
			ON CONFLICT (tenant_id, user_id) DO UPDATE SET secret_enc = $3, enabled = false, verified_at = NULL
		`, r.tenantID, userID, secretEnc)
		return err
	})
}

func (r *sharedMFARepo) ConfirmTOTP(ctx context.Context, userID string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE mfa_totp SET verified_at = NOW(), enabled = true WHERE tenant_id = $1 AND user_id = $2`,
			r.tenantID, userID)
		return err
	})
}

func (r *sharedMFARepo) GetTOTP(ctx context.Context, userID string) (*repository.MFATOTP, error) {
	const query = `
		SELECT user_id, secret_enc, verified_at, last_used_at, created_at
		FROM mfa_totp WHERE tenant_id = $1 AND user_id = $2
	`
	var mfa repository.MFATOTP
	err := r.pool.QueryRow(ctx, query, r.tenantID, userID).Scan(
		&mfa.UserID, &mfa.SecretEncrypted, &mfa.ConfirmedAt, &mfa.LastUsedAt, &mfa.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	// GDP schema has no updated_at; set UpdatedAt = CreatedAt.
	mfa.UpdatedAt = mfa.CreatedAt
	return &mfa, nil
}

func (r *sharedMFARepo) UpdateTOTPUsedAt(ctx context.Context, userID string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE mfa_totp SET last_used_at = NOW() WHERE tenant_id = $1 AND user_id = $2`,
			r.tenantID, userID)
		return err
	})
}

func (r *sharedMFARepo) DisableTOTP(ctx context.Context, userID string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM mfa_totp WHERE tenant_id = $1 AND user_id = $2`,
			r.tenantID, userID)
		return err
	})
}

// ─── Recovery Codes ────────────────────────────────────────────────

func (r *sharedMFARepo) SetRecoveryCodes(ctx context.Context, userID string, hashes []string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		// Delete existing codes
		_, err := tx.Exec(ctx,
			`DELETE FROM mfa_recovery_code WHERE tenant_id = $1 AND user_id = $2`,
			r.tenantID, userID)
		if err != nil {
			return err
		}
		// Batch INSERT all recovery codes in a single round-trip.
		batch := &pgx.Batch{}
		for _, hash := range hashes {
			batch.Queue(
				`INSERT INTO mfa_recovery_code (tenant_id, user_id, code_hash, created_at) VALUES ($1, $2, $3, NOW())`,
				r.tenantID, userID, hash,
			)
		}
		if batch.Len() == 0 {
			return nil
		}
		br := tx.SendBatch(ctx, batch)
		for i := 0; i < batch.Len(); i++ {
			if _, err := br.Exec(); err != nil {
				_ = br.Close()
				return err
			}
		}
		return br.Close()
	})
}

func (r *sharedMFARepo) DeleteRecoveryCodes(ctx context.Context, userID string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM mfa_recovery_code WHERE tenant_id = $1 AND user_id = $2`,
			r.tenantID, userID)
		return err
	})
}

func (r *sharedMFARepo) UseRecoveryCode(ctx context.Context, userID, hash string) (bool, error) {
	var used bool
	err := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM mfa_recovery_code WHERE tenant_id = $1 AND user_id = $2 AND code_hash = $3 AND used_at IS NULL`,
			r.tenantID, userID, hash)
		if err != nil {
			return err
		}
		used = tag.RowsAffected() > 0
		return nil
	})
	return used, err
}

// ─── Trusted Devices ───────────────────────────────────────────────

func (r *sharedMFARepo) AddTrustedDevice(ctx context.Context, userID, deviceHash string, expiresAt time.Time) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO mfa_trusted_device (tenant_id, user_id, device_hash, expires_at, created_at)
			VALUES ($1, $2, $3, $4, NOW())
			ON CONFLICT (tenant_id, user_id, device_hash) DO UPDATE SET expires_at = $4
		`, r.tenantID, userID, deviceHash, expiresAt)
		return err
	})
}

func (r *sharedMFARepo) IsTrustedDevice(ctx context.Context, userID, deviceHash string) (bool, error) {
	const query = `
		SELECT EXISTS (
			SELECT 1 FROM mfa_trusted_device
			WHERE tenant_id = $1 AND user_id = $2 AND device_hash = $3 AND expires_at > NOW()
		)
	`
	var exists bool
	err := r.pool.QueryRow(ctx, query, r.tenantID, userID, deviceHash).Scan(&exists)
	return exists, err
}
