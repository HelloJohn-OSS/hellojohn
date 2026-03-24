package mysql_shared

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// ─── helpers ──────────────────────────────────────────────────────

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// sanitizeIP validates an IP string for safe storage in MySQL VARCHAR(45).
func sanitizeIP(raw string) any {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if i := strings.Index(raw, ","); i >= 0 {
		raw = strings.TrimSpace(raw[:i])
	}
	host := raw
	if h, _, err := net.SplitHostPort(raw); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	log.Printf("[WARN] mysql_shared: sanitizeIP: invalid IP address %q will be stored as NULL", raw)
	return nil
}

// ─── sharedConsentRepo ────────────────────────────────────────────

type sharedConsentRepo struct {
	db       *sql.DB
	tenantID uuid.UUID
}

func (r *sharedConsentRepo) Upsert(ctx context.Context, _, userID, clientID string, scopes []string) (*repository.Consent, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: marshal scopes: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO user_consent (tenant_id, user_id, client_id, scopes, granted_at, updated_at)
		VALUES (?, ?, ?, ?, NOW(), NOW())
		ON DUPLICATE KEY UPDATE scopes = VALUES(scopes), updated_at = NOW(), revoked_at = NULL
	`, r.tenantID.String(), userID, clientID, scopesJSON)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: upsert consent: %w", err)
	}

	var consent repository.Consent
	var scopesRaw []byte
	err = tx.QueryRowContext(ctx, `
		SELECT id, granted_at, updated_at
		FROM user_consent
		WHERE tenant_id = ? AND user_id = ? AND client_id = ?
	`, r.tenantID.String(), userID, clientID).Scan(
		&consent.ID, &consent.GrantedAt, &consent.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: select after upsert consent: %w", err)
	}
	_ = scopesRaw // scopes already known

	consent.TenantID = r.tenantID.String()
	consent.UserID = userID
	consent.ClientID = clientID
	consent.Scopes = scopes

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("mysql_shared: commit upsert consent: %w", err)
	}
	return &consent, nil
}

func (r *sharedConsentRepo) Get(ctx context.Context, _, userID, clientID string) (*repository.Consent, error) {
	const query = `
		SELECT id, tenant_id, user_id, client_id, scopes, granted_at, updated_at, revoked_at
		FROM user_consent WHERE tenant_id = ? AND user_id = ? AND client_id = ?
	`
	var c repository.Consent
	var scopesRaw []byte
	err := r.db.QueryRowContext(ctx, query, r.tenantID.String(), userID, clientID).Scan(
		&c.ID, &c.TenantID, &c.UserID, &c.ClientID,
		&scopesRaw, &c.GrantedAt, &c.UpdatedAt, &c.RevokedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(scopesRaw) > 0 {
		if err := json.Unmarshal(scopesRaw, &c.Scopes); err != nil {
			log.Printf("[WARN] mysql_shared: json.Unmarshal scopes for consent %s: %v", c.ID, err)
		}
	}
	return &c, nil
}

func (r *sharedConsentRepo) ListByUser(ctx context.Context, _, userID string, activeOnly bool) ([]repository.Consent, error) {
	query := `SELECT id, tenant_id, user_id, client_id, scopes, granted_at, updated_at, revoked_at
	          FROM user_consent WHERE tenant_id = ? AND user_id = ?`
	if activeOnly {
		query += " AND revoked_at IS NULL"
	}
	query += " ORDER BY granted_at DESC"

	rows, err := r.db.QueryContext(ctx, query, r.tenantID.String(), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var consents []repository.Consent
	for rows.Next() {
		var c repository.Consent
		var scopesRaw []byte
		if err := rows.Scan(&c.ID, &c.TenantID, &c.UserID, &c.ClientID, &scopesRaw, &c.GrantedAt, &c.UpdatedAt, &c.RevokedAt); err != nil {
			return nil, err
		}
		if len(scopesRaw) > 0 {
			if err := json.Unmarshal(scopesRaw, &c.Scopes); err != nil {
				log.Printf("[WARN] mysql_shared: json.Unmarshal scopes for consent %s: %v", c.ID, err)
			}
		}
		consents = append(consents, c)
	}
	return consents, rows.Err()
}

func (r *sharedConsentRepo) ListAll(ctx context.Context, _ string, limit, offset int, activeOnly bool) ([]repository.Consent, int, error) {
	// Count
	countQuery := `SELECT COUNT(*) FROM user_consent WHERE tenant_id = ?`
	if activeOnly {
		countQuery += " AND revoked_at IS NULL"
	}
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, r.tenantID.String()).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Data
	dataQuery := `SELECT id, tenant_id, user_id, client_id, scopes, granted_at, updated_at, revoked_at
	              FROM user_consent WHERE tenant_id = ?`
	if activeOnly {
		dataQuery += " AND revoked_at IS NULL"
	}
	dataQuery += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"

	rows, err := r.db.QueryContext(ctx, dataQuery, r.tenantID.String(), limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var consents []repository.Consent
	for rows.Next() {
		var c repository.Consent
		var scopesRaw []byte
		if err := rows.Scan(&c.ID, &c.TenantID, &c.UserID, &c.ClientID, &scopesRaw, &c.GrantedAt, &c.UpdatedAt, &c.RevokedAt); err != nil {
			return nil, 0, err
		}
		if len(scopesRaw) > 0 {
			if err := json.Unmarshal(scopesRaw, &c.Scopes); err != nil {
				log.Printf("[WARN] mysql_shared: json.Unmarshal scopes for consent %s: %v", c.ID, err)
			}
		}
		consents = append(consents, c)
	}
	return consents, total, rows.Err()
}

func (r *sharedConsentRepo) Revoke(ctx context.Context, _, userID, clientID string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		`UPDATE user_consent SET revoked_at = NOW() WHERE tenant_id = ? AND user_id = ? AND client_id = ?`,
		r.tenantID.String(), userID, clientID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return repository.ErrNotFound
	}
	return tx.Commit()
}

// ─── sharedWebhookRepo ───────────────────────────────────────────

type sharedWebhookRepo struct {
	db       *sql.DB
	tenantID uuid.UUID
}

func (r *sharedWebhookRepo) InsertDelivery(ctx context.Context, delivery *repository.WebhookDelivery) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
		INSERT INTO webhook_delivery (id, tenant_id, webhook_id, event_type, payload, status, attempts, next_retry, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, delivery.ID, r.tenantID.String(), delivery.WebhookID, delivery.EventType, delivery.Payload,
		delivery.Status, delivery.Attempts, delivery.NextRetryAt, delivery.CreatedAt)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *sharedWebhookRepo) FetchPending(ctx context.Context, limit int) ([]*repository.WebhookDelivery, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `
		SELECT id, webhook_id, event_type, payload, status, attempts,
		       last_attempt, next_retry, http_status, response_body, created_at
		FROM webhook_delivery
		WHERE tenant_id = ? AND status IN ('pending', 'failed') AND next_retry <= NOW()
		ORDER BY next_retry ASC
		LIMIT ?
		FOR UPDATE SKIP LOCKED
	`, r.tenantID.String(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deliveries []*repository.WebhookDelivery
	for rows.Next() {
		var d repository.WebhookDelivery
		if err := rows.Scan(
			&d.ID, &d.WebhookID, &d.EventType, &d.Payload, &d.Status, &d.Attempts,
			&d.LastAttemptAt, &d.NextRetryAt, &d.HTTPStatus, &d.ResponseBody, &d.CreatedAt,
		); err != nil {
			return nil, err
		}
		deliveries = append(deliveries, &d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("mysql_shared: commit fetch pending: %w", err)
	}
	return deliveries, nil
}

func (r *sharedWebhookRepo) UpdateDeliveryStatus(ctx context.Context, id string, status string, attempts int, nextRetry, lastAttempt *time.Time, httpStatus *int, responseBody *string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
		UPDATE webhook_delivery SET
			status = ?, attempts = ?, next_retry = ?,
			last_attempt = ?, http_status = ?, response_body = ?
		WHERE tenant_id = ? AND id = ?
	`, status, attempts, nextRetry, lastAttempt, httpStatus, responseBody, r.tenantID.String(), id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *sharedWebhookRepo) ListDeliveries(ctx context.Context, webhookID string, limit, offset int, filter repository.WebhookDeliveryFilter) ([]*repository.WebhookDelivery, error) {
	args := []any{r.tenantID.String(), webhookID}
	conditions := []string{"tenant_id = ?", "webhook_id = ?"}

	if !filter.From.IsZero() {
		conditions = append(conditions, "created_at >= ?")
		args = append(args, filter.From.UTC())
	}
	if !filter.To.IsZero() {
		conditions = append(conditions, "created_at <= ?")
		args = append(args, filter.To.UTC())
	}
	if filter.Result != "" {
		conditions = append(conditions, "status = ?")
		args = append(args, filter.Result)
	}
	if filter.Event != "" {
		conditions = append(conditions, "event_type = ?")
		args = append(args, filter.Event)
	}

	args = append(args, limit+1, offset)
	query := fmt.Sprintf(`
		SELECT id, webhook_id, event_type, payload, status,
		       attempts, last_attempt, next_retry, http_status, response_body, created_at
		FROM webhook_delivery
		WHERE %s
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`, strings.Join(conditions, " AND "))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var deliveries []*repository.WebhookDelivery
	for rows.Next() {
		d := &repository.WebhookDelivery{}
		var payload []byte
		if err := rows.Scan(
			&d.ID, &d.WebhookID, &d.EventType, &payload,
			&d.Status, &d.Attempts, &d.LastAttemptAt, &d.NextRetryAt,
			&d.HTTPStatus, &d.ResponseBody, &d.CreatedAt,
		); err != nil {
			return nil, err
		}
		d.Payload = json.RawMessage(payload)
		deliveries = append(deliveries, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Trim the extra sentinel row used to detect pagination.
	if len(deliveries) > limit {
		deliveries = deliveries[:limit]
	}
	return deliveries, nil
}

// ─── sharedInvitationRepo ────────────────────────────────────────

type sharedInvitationRepo struct {
	db       *sql.DB
	tenantID uuid.UUID
}

func (r *sharedInvitationRepo) Create(ctx context.Context, in repository.CreateInvitationInput) (*repository.Invitation, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	rolesJSON, err := json.Marshal(in.Roles)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: marshal roles: %w", err)
	}

	id := uuid.New().String()
	_, err = tx.ExecContext(ctx, `
		INSERT INTO invitation (id, tenant_id, email, token_hash, invited_by, roles, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, id, r.tenantID.String(), in.Email, in.TokenHash, in.InvitedByID, rolesJSON, in.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: insert invitation: %w", err)
	}

	var out repository.Invitation
	var rolesRaw []byte
	err = tx.QueryRowContext(ctx, `
		SELECT id, tenant_id, email, token_hash, status, invited_by, roles,
		       expires_at, accepted_at, created_at, updated_at
		FROM invitation
		WHERE tenant_id = ? AND id = ?
	`, r.tenantID.String(), id).Scan(
		&out.ID, &out.TenantID, &out.Email, &out.TokenHash, &out.Status,
		&out.InvitedByID, &rolesRaw, &out.ExpiresAt, &out.AcceptedAt,
		&out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: select after insert invitation: %w", err)
	}
	if len(rolesRaw) > 0 {
		if err := json.Unmarshal(rolesRaw, &out.Roles); err != nil {
			log.Printf("[WARN] mysql_shared: json.Unmarshal roles for invitation %s: %v", out.ID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("mysql_shared: commit create invitation: %w", err)
	}
	return &out, nil
}

func (r *sharedInvitationRepo) GetByTokenHash(ctx context.Context, _, hash string) (*repository.Invitation, error) {
	const q = `
		SELECT id, tenant_id, email, token_hash, status, invited_by, roles,
		       expires_at, accepted_at, created_at, updated_at
		FROM invitation
		WHERE tenant_id = ? AND token_hash = ?
	`
	var out repository.Invitation
	var rolesRaw []byte
	err := r.db.QueryRowContext(ctx, q, r.tenantID.String(), hash).Scan(
		&out.ID, &out.TenantID, &out.Email, &out.TokenHash, &out.Status,
		&out.InvitedByID, &rolesRaw, &out.ExpiresAt, &out.AcceptedAt,
		&out.CreatedAt, &out.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(rolesRaw) > 0 {
		if err := json.Unmarshal(rolesRaw, &out.Roles); err != nil {
			log.Printf("[WARN] mysql_shared: json.Unmarshal roles for invitation %s: %v", out.ID, err)
		}
	}
	return &out, nil
}

func (r *sharedInvitationRepo) GetByID(ctx context.Context, _, id string) (*repository.Invitation, error) {
	const q = `
		SELECT id, tenant_id, email, token_hash, status, invited_by, roles,
		       expires_at, accepted_at, created_at, updated_at
		FROM invitation
		WHERE tenant_id = ? AND id = ?
	`
	var out repository.Invitation
	var rolesRaw []byte
	err := r.db.QueryRowContext(ctx, q, r.tenantID.String(), id).Scan(
		&out.ID, &out.TenantID, &out.Email, &out.TokenHash, &out.Status,
		&out.InvitedByID, &rolesRaw, &out.ExpiresAt, &out.AcceptedAt,
		&out.CreatedAt, &out.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(rolesRaw) > 0 {
		if err := json.Unmarshal(rolesRaw, &out.Roles); err != nil {
			log.Printf("[WARN] mysql_shared: json.Unmarshal roles for invitation %s: %v", out.ID, err)
		}
	}
	return &out, nil
}

func (r *sharedInvitationRepo) List(ctx context.Context, _ string, status *repository.InvitationStatus, limit, offset int) ([]repository.Invitation, error) {
	q := `
		SELECT id, tenant_id, email, token_hash, status, invited_by, roles,
		       expires_at, accepted_at, created_at, updated_at
		FROM invitation
		WHERE tenant_id = ?
	`
	args := []any{r.tenantID.String()}

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
		var item repository.Invitation
		var rolesRaw []byte
		if err := rows.Scan(
			&item.ID, &item.TenantID, &item.Email, &item.TokenHash, &item.Status,
			&item.InvitedByID, &rolesRaw, &item.ExpiresAt, &item.AcceptedAt,
			&item.CreatedAt, &item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if len(rolesRaw) > 0 {
			if err := json.Unmarshal(rolesRaw, &item.Roles); err != nil {
				log.Printf("[WARN] mysql_shared: json.Unmarshal roles for invitation %s: %v", item.ID, err)
			}
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *sharedInvitationRepo) UpdateStatus(ctx context.Context, _, id string, newStatus repository.InvitationStatus, acceptedAt *time.Time) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, `
		UPDATE invitation
		SET status = ?, accepted_at = ?, updated_at = NOW()
		WHERE tenant_id = ? AND id = ? AND status = 'pending'
	`, string(newStatus), acceptedAt, r.tenantID.String(), id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return repository.ErrInvitationNotPending
	}
	return tx.Commit()
}

func (r *sharedInvitationRepo) Delete(ctx context.Context, _, id string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, `DELETE FROM invitation WHERE tenant_id = ? AND id = ?`, r.tenantID.String(), id)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return repository.ErrNotFound
	}
	return tx.Commit()
}

// ─── sharedWebAuthnRepo ──────────────────────────────────────────

type sharedWebAuthnRepo struct {
	db       *sql.DB
	tenantID uuid.UUID
}

func (r *sharedWebAuthnRepo) Create(ctx context.Context, _ string, cred repository.WebAuthnCredential) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	transportsJSON, err := json.Marshal(cred.Transports)
	if err != nil {
		return fmt.Errorf("mysql_shared: marshal transports: %w", err)
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO webauthn_credential
			(tenant_id, user_id, credential_id, public_key, aaguid, sign_count,
			 transports, user_verified, backup_eligible, backup_state, name)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, r.tenantID.String(), cred.UserID, cred.CredentialID, cred.PublicKey, cred.AAGUID,
		int64(cred.SignCount), transportsJSON, cred.UserVerified, cred.BackupEligible,
		cred.BackupState, cred.Name)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *sharedWebAuthnRepo) GetByUserID(ctx context.Context, _, userID string) ([]repository.WebAuthnCredential, error) {
	const q = `
		SELECT id, tenant_id, user_id, credential_id, public_key, aaguid, sign_count,
		       transports, user_verified, backup_eligible, backup_state, name,
		       created_at, last_used_at
		FROM webauthn_credential
		WHERE tenant_id = ? AND user_id = ?
		ORDER BY created_at ASC
	`
	rows, err := r.db.QueryContext(ctx, q, r.tenantID.String(), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]repository.WebAuthnCredential, 0)
	for rows.Next() {
		item, err := scanMySQLWebAuthnCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *sharedWebAuthnRepo) GetByCredentialID(ctx context.Context, _ string, credID []byte) (*repository.WebAuthnCredential, error) {
	const q = `
		SELECT id, tenant_id, user_id, credential_id, public_key, aaguid, sign_count,
		       transports, user_verified, backup_eligible, backup_state, name,
		       created_at, last_used_at
		FROM webauthn_credential
		WHERE tenant_id = ? AND credential_id = ?
	`
	rows, err := r.db.QueryContext(ctx, q, r.tenantID.String(), credID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, repository.ErrNotFound
	}
	item, err := scanMySQLWebAuthnCredential(rows)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *sharedWebAuthnRepo) UpdateSignCount(ctx context.Context, _ string, credID []byte, newCount uint32) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		`UPDATE webauthn_credential SET sign_count = ? WHERE tenant_id = ? AND credential_id = ?`,
		int64(newCount), r.tenantID.String(), credID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return repository.ErrNotFound
	}
	return tx.Commit()
}

func (r *sharedWebAuthnRepo) UpdateLastUsed(ctx context.Context, _ string, credID []byte) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		`UPDATE webauthn_credential SET last_used_at = NOW() WHERE tenant_id = ? AND credential_id = ?`,
		r.tenantID.String(), credID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return repository.ErrNotFound
	}
	return tx.Commit()
}

func (r *sharedWebAuthnRepo) Delete(ctx context.Context, _, id string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`DELETE FROM webauthn_credential WHERE tenant_id = ? AND id = ?`,
		r.tenantID.String(), id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// scanMySQLWebAuthnCredential scans a single webauthn_credential row.
// Transports is stored as JSON in MySQL (TEXT[] in PG).
func scanMySQLWebAuthnCredential(rows *sql.Rows) (repository.WebAuthnCredential, error) {
	var (
		item           repository.WebAuthnCredential
		signCount      int64
		lastUsed       *time.Time
		transportsRaw  []byte
	)
	err := rows.Scan(
		&item.ID, &item.TenantID, &item.UserID, &item.CredentialID,
		&item.PublicKey, &item.AAGUID, &signCount,
		&transportsRaw, &item.UserVerified, &item.BackupEligible, &item.BackupState,
		&item.Name, &item.CreatedAt, &lastUsed,
	)
	if err != nil {
		return repository.WebAuthnCredential{}, err
	}
	item.SignCount = uint32(signCount)
	item.LastUsedAt = lastUsed
	if len(transportsRaw) > 0 {
		if err := json.Unmarshal(transportsRaw, &item.Transports); err != nil {
			log.Printf("[WARN] mysql_shared: json.Unmarshal transports for credential %s: %v", item.ID, err)
		}
	}
	return item, nil
}

// ─── sharedAuditRepo ─────────────────────────────────────────────

type sharedAuditRepo struct {
	db       *sql.DB
	tenantID uuid.UUID
}

func (r *sharedAuditRepo) InsertBatch(ctx context.Context, events []audit.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	const stmt = `
		INSERT INTO audit_log (
			id, tenant_id, event_type, actor_id, actor_type,
			target_id, target_type, ip_address, user_agent,
			metadata, result, created_at
		) VALUES (
			?, ?, ?, ?, ?,
			?, ?, ?, ?,
			?, ?, ?
		)
	`

	for _, e := range events {
		meta, err := json.Marshal(e.Metadata)
		if err != nil {
			log.Printf("[WARN] mysql_shared: audit_log: json.Marshal metadata for event %s: %v - storing NULL", e.ID, err)
			meta = []byte("{}")
		}
		if meta == nil {
			meta = []byte("{}")
		}

		ip := sanitizeIP(e.IPAddress)

		_, err = tx.ExecContext(ctx, stmt,
			e.ID,
			r.tenantID.String(),
			string(e.Type),
			nullIfEmpty(e.ActorID),
			e.ActorType,
			nullIfEmpty(e.TargetID),
			nullIfEmpty(e.TargetType),
			ip,
			nullIfEmpty(e.UserAgent),
			meta,
			e.Result,
			e.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("mysql_shared audit insert batch exec: %w", err)
		}
	}

	return tx.Commit()
}

func (r *sharedAuditRepo) List(ctx context.Context, filter repository.AuditFilter) ([]audit.AuditEvent, int64, error) {
	var (
		where []string
		args  []any
	)

	// Always filter by tenant
	where = append(where, "tenant_id = ?")
	args = append(args, r.tenantID.String())

	if filter.EventType != "" {
		where = append(where, "event_type = ?")
		args = append(args, filter.EventType)
	}
	if filter.ActorID != "" {
		where = append(where, "actor_id = ?")
		args = append(args, filter.ActorID)
	}
	if filter.TargetID != "" {
		where = append(where, "target_id = ?")
		args = append(args, filter.TargetID)
	}
	if filter.Result != "" {
		where = append(where, "result = ?")
		args = append(args, filter.Result)
	}
	if !filter.From.IsZero() {
		where = append(where, "created_at >= ?")
		args = append(args, filter.From)
	}
	if !filter.To.IsZero() {
		where = append(where, "created_at <= ?")
		args = append(args, filter.To)
	}

	whereClause := "WHERE " + strings.Join(where, " AND ")

	// Count
	var total int64
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	if err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log "+whereClause, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("mysql_shared audit count: %w", err)
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	dataQuery := fmt.Sprintf(`
		SELECT id, event_type, actor_id, actor_type,
		       target_id, target_type, ip_address, user_agent,
		       metadata, result, created_at
		FROM audit_log %s
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`, whereClause)
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("mysql_shared audit list: %w", err)
	}
	defer rows.Close()

	var events []audit.AuditEvent
	for rows.Next() {
		var e audit.AuditEvent
		var eventType string
		var actorID, targetID, targetType, ipAddr, ua *string
		var metaBytes []byte

		if err := rows.Scan(
			&e.ID, &eventType, &actorID, &e.ActorType,
			&targetID, &targetType, &ipAddr, &ua,
			&metaBytes, &e.Result, &e.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("mysql_shared audit scan: %w", err)
		}

		e.TenantID = r.tenantID.String()
		e.Type = audit.EventType(eventType)
		if actorID != nil {
			e.ActorID = *actorID
		}
		if targetID != nil {
			e.TargetID = *targetID
		}
		if targetType != nil {
			e.TargetType = *targetType
		}
		if ipAddr != nil {
			e.IPAddress = *ipAddr
		}
		if ua != nil {
			e.UserAgent = *ua
		}
		if len(metaBytes) > 0 {
			if err := json.Unmarshal(metaBytes, &e.Metadata); err != nil {
				log.Printf("[WARN] mysql_shared: audit_log: json.Unmarshal metadata for event %s: %v - using empty metadata", e.ID, err)
				e.Metadata = map[string]any{"_metadata_parse_error": err.Error()}
			}
		}

		events = append(events, e)
	}

	return events, total, rows.Err()
}

func (r *sharedAuditRepo) GetByID(ctx context.Context, id string) (*audit.AuditEvent, error) {
	const q = `
		SELECT id, event_type, actor_id, actor_type,
		       target_id, target_type, ip_address, user_agent,
		       metadata, result, created_at
		FROM audit_log WHERE tenant_id = ? AND id = ?
	`

	var e audit.AuditEvent
	var eventType string
	var actorID, targetID, targetType, ipAddr, ua *string
	var metaBytes []byte

	err := r.db.QueryRowContext(ctx, q, r.tenantID.String(), id).Scan(
		&e.ID, &eventType, &actorID, &e.ActorType,
		&targetID, &targetType, &ipAddr, &ua,
		&metaBytes, &e.Result, &e.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("mysql_shared audit get by id: %w", err)
	}

	e.TenantID = r.tenantID.String()
	e.Type = audit.EventType(eventType)
	if actorID != nil {
		e.ActorID = *actorID
	}
	if targetID != nil {
		e.TargetID = *targetID
	}
	if targetType != nil {
		e.TargetType = *targetType
	}
	if ipAddr != nil {
		e.IPAddress = *ipAddr
	}
	if ua != nil {
		e.UserAgent = *ua
	}
	if len(metaBytes) > 0 {
		if err := json.Unmarshal(metaBytes, &e.Metadata); err != nil {
			log.Printf("[WARN] mysql_shared audit: json.Unmarshal metadata for event %s: %v", e.ID, err)
			e.Metadata = map[string]any{"_metadata_parse_error": err.Error()}
		}
	}

	return &e, nil
}

func (r *sharedAuditRepo) Purge(ctx context.Context, before time.Time) (int64, error) {
	var total int64
	batchSize := 1000

	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}

		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			return total, fmt.Errorf("mysql_shared audit purge: begin tx: %w", err)
		}

		result, err := tx.ExecContext(ctx, `
			DELETE FROM audit_log
			WHERE tenant_id = ? AND created_at < ?
			LIMIT ?
		`, r.tenantID.String(), before, batchSize)
		if err != nil {
			tx.Rollback()
			return total, fmt.Errorf("mysql_shared audit purge: %w", err)
		}
		n, _ := result.RowsAffected()

		if err := tx.Commit(); err != nil {
			return total, fmt.Errorf("mysql_shared audit purge: commit: %w", err)
		}

		total += n
		if n < int64(batchSize) {
			return total, nil
		}
	}
}

// ─── DeleteAllForTenant ──────────────────────────────────────────
// Cascade-deletes ALL data for a tenant from the shared database.
// Used for tenant deprovisioning/cleanup.

func DeleteAllForTenant(ctx context.Context, db *sql.DB, tenantID uuid.UUID) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	// Delete in FK-safe order (reverse of creation)
	tables := []string{
		"password_history",
		"webauthn_credential",
		"invitation",
		"webhook_delivery",
		"webhook",
		"audit_log",
		"sessions",
		"user_consent",
		"mfa_trusted_device",
		"mfa_recovery_code",
		"mfa_totp",
		"password_reset_token",
		"email_verification_token",
		"rbac_user_role",
		"rbac_role",
		"refresh_token",
		"identity",
		"app_user",
	}

	for _, table := range tables {
		_, err := tx.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s WHERE tenant_id = ?", table), tenantID.String())
		if err != nil {
			return fmt.Errorf("mysql_shared: delete %s for tenant %s: %w", table, tenantID, err)
		}
	}

	return tx.Commit()
}
