package mysql_shared

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// ─── sharedMFARepo ────────────────────────────────────────────────

// sharedMFARepo implements repository.MFARepository for Global Data Plane (MySQL).
// GDP schema differences from isolated adapter:
//   - Column: secret_enc   (not secret_encrypted)
//   - Column: verified_at  (not confirmed_at)
//   - No updated_at or last_used_at in mfa_totp
//   - Has additional columns: algorithm, digits, period, enabled
type sharedMFARepo struct {
	db       *sql.DB
	tenantID uuid.UUID
}

func (r *sharedMFARepo) UpsertTOTP(ctx context.Context, userID, secretEnc string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
		INSERT INTO mfa_totp (tenant_id, user_id, secret_enc, created_at)
		VALUES (?, ?, ?, NOW())
		ON DUPLICATE KEY UPDATE secret_enc = VALUES(secret_enc), enabled = false, verified_at = NULL
	`, r.tenantID.String(), userID, secretEnc)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *sharedMFARepo) ConfirmTOTP(ctx context.Context, userID string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`UPDATE mfa_totp SET verified_at = NOW(), enabled = true WHERE tenant_id = ? AND user_id = ?`,
		r.tenantID.String(), userID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *sharedMFARepo) GetTOTP(ctx context.Context, userID string) (*repository.MFATOTP, error) {
	const query = `
		SELECT user_id, secret_enc, verified_at, last_used_at, created_at
		FROM mfa_totp WHERE tenant_id = ? AND user_id = ?
	`
	var mfa repository.MFATOTP
	err := r.db.QueryRowContext(ctx, query, r.tenantID.String(), userID).Scan(
		&mfa.UserID, &mfa.SecretEncrypted, &mfa.ConfirmedAt, &mfa.LastUsedAt, &mfa.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
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
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`UPDATE mfa_totp SET last_used_at = NOW() WHERE tenant_id = ? AND user_id = ?`,
		r.tenantID.String(), userID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *sharedMFARepo) DisableTOTP(ctx context.Context, userID string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`DELETE FROM mfa_totp WHERE tenant_id = ? AND user_id = ?`,
		r.tenantID.String(), userID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// ─── Recovery Codes ────────────────────────────────────────────────

func (r *sharedMFARepo) SetRecoveryCodes(ctx context.Context, userID string, hashes []string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete existing codes
	_, err = tx.ExecContext(ctx,
		`DELETE FROM mfa_recovery_code WHERE tenant_id = ? AND user_id = ?`,
		r.tenantID.String(), userID)
	if err != nil {
		return err
	}

	// Insert all recovery codes individually in the transaction.
	for _, hash := range hashes {
		_, err = tx.ExecContext(ctx,
			`INSERT INTO mfa_recovery_code (tenant_id, user_id, code_hash, created_at) VALUES (?, ?, ?, NOW())`,
			r.tenantID.String(), userID, hash)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *sharedMFARepo) DeleteRecoveryCodes(ctx context.Context, userID string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`DELETE FROM mfa_recovery_code WHERE tenant_id = ? AND user_id = ?`,
		r.tenantID.String(), userID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *sharedMFARepo) UseRecoveryCode(ctx context.Context, userID, hash string) (bool, error) {
	var used bool
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		`DELETE FROM mfa_recovery_code WHERE tenant_id = ? AND user_id = ? AND code_hash = ? AND used_at IS NULL`,
		r.tenantID.String(), userID, hash)
	if err != nil {
		return false, err
	}
	n, _ := result.RowsAffected()
	used = n > 0

	if err := tx.Commit(); err != nil {
		return false, err
	}
	return used, nil
}

// ─── Trusted Devices ───────────────────────────────────────────────

func (r *sharedMFARepo) AddTrustedDevice(ctx context.Context, userID, deviceHash string, expiresAt time.Time) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
		INSERT INTO mfa_trusted_device (tenant_id, user_id, device_hash, expires_at, created_at)
		VALUES (?, ?, ?, ?, NOW())
		ON DUPLICATE KEY UPDATE expires_at = VALUES(expires_at)
	`, r.tenantID.String(), userID, deviceHash, expiresAt)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *sharedMFARepo) IsTrustedDevice(ctx context.Context, userID, deviceHash string) (bool, error) {
	const query = `
		SELECT EXISTS (
			SELECT 1 FROM mfa_trusted_device
			WHERE tenant_id = ? AND user_id = ? AND device_hash = ? AND expires_at > NOW()
		)
	`
	var exists bool
	err := r.db.QueryRowContext(ctx, query, r.tenantID.String(), userID, deviceHash).Scan(&exists)
	return exists, err
}
