package mysql

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// Compile-time interface check.
var _ repository.WebAuthnRepository = (*webAuthnMysqlRepo)(nil)

type webAuthnMysqlRepo struct {
	db *sql.DB
}

func (r *webAuthnMysqlRepo) Create(ctx context.Context, tenantID string, cred repository.WebAuthnCredential) error {
	transportsJSON, err := json.Marshal(cred.Transports)
	if err != nil {
		return err
	}

	const q = `
		INSERT INTO webauthn_credential
			(tenant_id, user_id, credential_id, public_key, aaguid, sign_count,
			 transports, user_verified, backup_eligible, backup_state, name)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = r.db.ExecContext(ctx, q,
		tenantID,
		cred.UserID,
		cred.CredentialID,
		cred.PublicKey,
		cred.AAGUID,
		cred.SignCount,
		transportsJSON,
		boolToTinyInt(cred.UserVerified),
		boolToTinyInt(cred.BackupEligible),
		boolToTinyInt(cred.BackupState),
		cred.Name,
	)
	return err
}

func (r *webAuthnMysqlRepo) GetByUserID(ctx context.Context, tenantID, userID string) ([]repository.WebAuthnCredential, error) {
	const q = `
		SELECT id, tenant_id, user_id, credential_id, public_key, aaguid, sign_count,
		       transports, user_verified, backup_eligible, backup_state, name,
		       created_at, last_used_at
		FROM webauthn_credential
		WHERE tenant_id = ? AND user_id = ?
		ORDER BY created_at ASC
	`

	rows, err := r.db.QueryContext(ctx, q, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]repository.WebAuthnCredential, 0)
	for rows.Next() {
		item, err := scanWebAuthnCredentialRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *webAuthnMysqlRepo) GetByCredentialID(ctx context.Context, tenantID string, credID []byte) (*repository.WebAuthnCredential, error) {
	const q = `
		SELECT id, tenant_id, user_id, credential_id, public_key, aaguid, sign_count,
		       transports, user_verified, backup_eligible, backup_state, name,
		       created_at, last_used_at
		FROM webauthn_credential
		WHERE tenant_id = ? AND credential_id = ?
	`

	row := r.db.QueryRowContext(ctx, q, tenantID, credID)
	item, err := scanWebAuthnCredentialRow(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *webAuthnMysqlRepo) UpdateSignCount(ctx context.Context, tenantID string, credID []byte, newCount uint32) error {
	const q = `UPDATE webauthn_credential SET sign_count = ? WHERE tenant_id = ? AND credential_id = ?`
	_, err := r.db.ExecContext(ctx, q, newCount, tenantID, credID)
	return err
}

func (r *webAuthnMysqlRepo) UpdateLastUsed(ctx context.Context, tenantID string, credID []byte) error {
	const q = `UPDATE webauthn_credential SET last_used_at = NOW(6) WHERE tenant_id = ? AND credential_id = ?`
	_, err := r.db.ExecContext(ctx, q, tenantID, credID)
	return err
}

func (r *webAuthnMysqlRepo) Delete(ctx context.Context, tenantID, id string) error {
	const q = `DELETE FROM webauthn_credential WHERE tenant_id = ? AND id = ?`
	_, err := r.db.ExecContext(ctx, q, tenantID, id)
	return err
}

type scanWebAuthnCredentialScanner interface {
	Scan(dest ...any) error
}

func scanWebAuthnCredentialRow(row scanWebAuthnCredentialScanner) (repository.WebAuthnCredential, error) {
	var (
		item           repository.WebAuthnCredential
		transportsJSON []byte
		signCount      uint64
		userVerified   int
		backupEligible int
		backupState    int
	)

	err := row.Scan(
		&item.ID,
		&item.TenantID,
		&item.UserID,
		&item.CredentialID,
		&item.PublicKey,
		&item.AAGUID,
		&signCount,
		&transportsJSON,
		&userVerified,
		&backupEligible,
		&backupState,
		&item.Name,
		&item.CreatedAt,
		&item.LastUsedAt,
	)
	if err != nil {
		return repository.WebAuthnCredential{}, err
	}

	item.SignCount = uint32(signCount)
	item.UserVerified = userVerified == 1
	item.BackupEligible = backupEligible == 1
	item.BackupState = backupState == 1
	if len(transportsJSON) > 0 {
		_ = json.Unmarshal(transportsJSON, &item.Transports)
	}
	if item.Transports == nil {
		item.Transports = []string{}
	}
	return item, nil
}

func boolToTinyInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
