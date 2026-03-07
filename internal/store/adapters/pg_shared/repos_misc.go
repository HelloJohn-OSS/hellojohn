package pg_shared

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

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

// sanitizeIP validates an IP string for safe use in PG INET cast.
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
	log.Printf("[WARN] pg_shared: sanitizeIP: invalid IP address %q will be stored as NULL", raw)
	return nil
}

// ─── sharedConsentRepo ────────────────────────────────────────────

type sharedConsentRepo struct {
	pool     *pgxpool.Pool
	tenantID uuid.UUID
}

func (r *sharedConsentRepo) Upsert(ctx context.Context, _, userID, clientID string, scopes []string) (*repository.Consent, error) {
	var consent repository.Consent
	err := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		const query = `
			INSERT INTO user_consent (tenant_id, user_id, client_id, scopes, granted_at, updated_at)
			VALUES ($1, $2, $3, $4, NOW(), NOW())
			ON CONFLICT (tenant_id, user_id, client_id)
			DO UPDATE SET scopes = $4, updated_at = NOW(), revoked_at = NULL
			RETURNING id, granted_at, updated_at
		`
		consent = repository.Consent{
			TenantID: r.tenantID.String(),
			UserID:   userID,
			ClientID: clientID,
			Scopes:   scopes,
		}
		return tx.QueryRow(ctx, query, r.tenantID, userID, clientID, scopes).Scan(
			&consent.ID, &consent.GrantedAt, &consent.UpdatedAt,
		)
	})
	if err != nil {
		return nil, err
	}
	return &consent, nil
}

func (r *sharedConsentRepo) Get(ctx context.Context, _, userID, clientID string) (*repository.Consent, error) {
	const query = `
		SELECT id, tenant_id, user_id, client_id, scopes, granted_at, updated_at, revoked_at
		FROM user_consent WHERE tenant_id = $1 AND user_id = $2 AND client_id = $3
	`
	var c repository.Consent
	err := r.pool.QueryRow(ctx, query, r.tenantID, userID, clientID).Scan(
		&c.ID, &c.TenantID, &c.UserID, &c.ClientID,
		&c.Scopes, &c.GrantedAt, &c.UpdatedAt, &c.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *sharedConsentRepo) ListByUser(ctx context.Context, _, userID string, activeOnly bool) ([]repository.Consent, error) {
	query := `SELECT id, tenant_id, user_id, client_id, scopes, granted_at, updated_at, revoked_at
	          FROM user_consent WHERE tenant_id = $1 AND user_id = $2`
	if activeOnly {
		query += " AND revoked_at IS NULL"
	}
	query += " ORDER BY granted_at DESC"

	rows, err := r.pool.Query(ctx, query, r.tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var consents []repository.Consent
	for rows.Next() {
		var c repository.Consent
		if err := rows.Scan(&c.ID, &c.TenantID, &c.UserID, &c.ClientID, &c.Scopes, &c.GrantedAt, &c.UpdatedAt, &c.RevokedAt); err != nil {
			return nil, err
		}
		consents = append(consents, c)
	}
	return consents, rows.Err()
}

func (r *sharedConsentRepo) ListAll(ctx context.Context, _ string, limit, offset int, activeOnly bool) ([]repository.Consent, int, error) {
	// Count
	countQuery := `SELECT COUNT(*) FROM user_consent WHERE tenant_id = $1`
	if activeOnly {
		countQuery += " AND revoked_at IS NULL"
	}
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, r.tenantID).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Data
	dataQuery := `SELECT id, tenant_id, user_id, client_id, scopes, granted_at, updated_at, revoked_at
	              FROM user_consent WHERE tenant_id = $1`
	if activeOnly {
		dataQuery += " AND revoked_at IS NULL"
	}
	dataQuery += " ORDER BY updated_at DESC LIMIT $2 OFFSET $3"

	rows, err := r.pool.Query(ctx, dataQuery, r.tenantID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var consents []repository.Consent
	for rows.Next() {
		var c repository.Consent
		if err := rows.Scan(&c.ID, &c.TenantID, &c.UserID, &c.ClientID, &c.Scopes, &c.GrantedAt, &c.UpdatedAt, &c.RevokedAt); err != nil {
			return nil, 0, err
		}
		consents = append(consents, c)
	}
	return consents, total, rows.Err()
}

func (r *sharedConsentRepo) Revoke(ctx context.Context, _, userID, clientID string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE user_consent SET revoked_at = NOW() WHERE tenant_id = $1 AND user_id = $2 AND client_id = $3`,
			r.tenantID, userID, clientID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

// ─── sharedWebhookRepo ───────────────────────────────────────────

type sharedWebhookRepo struct {
	pool     *pgxpool.Pool
	tenantID uuid.UUID
}

func (r *sharedWebhookRepo) InsertDelivery(ctx context.Context, delivery *repository.WebhookDelivery) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO webhook_delivery (id, tenant_id, webhook_id, event_type, payload, status, attempts, next_retry, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`, delivery.ID, r.tenantID, delivery.WebhookID, delivery.EventType, delivery.Payload,
			delivery.Status, delivery.Attempts, delivery.NextRetryAt, delivery.CreatedAt)
		return err
	})
}

func (r *sharedWebhookRepo) FetchPending(ctx context.Context, limit int) ([]*repository.WebhookDelivery, error) {
	var deliveries []*repository.WebhookDelivery
	err := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, webhook_id, event_type, payload, status, attempts,
			       last_attempt, next_retry, http_status, response_body, created_at
			FROM webhook_delivery
			WHERE tenant_id = $1 AND status IN ('pending', 'failed') AND next_retry <= NOW()
			ORDER BY next_retry ASC
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		`, r.tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var d repository.WebhookDelivery
			if err := rows.Scan(
				&d.ID, &d.WebhookID, &d.EventType, &d.Payload, &d.Status, &d.Attempts,
				&d.LastAttemptAt, &d.NextRetryAt, &d.HTTPStatus, &d.ResponseBody, &d.CreatedAt,
			); err != nil {
				return err
			}
			deliveries = append(deliveries, &d)
		}
		return rows.Err()
	})
	return deliveries, err
}

func (r *sharedWebhookRepo) UpdateDeliveryStatus(ctx context.Context, id string, status string, attempts int, nextRetry, lastAttempt *time.Time, httpStatus *int, responseBody *string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE webhook_delivery SET
				status = $3, attempts = $4, next_retry = $5,
				last_attempt = $6, http_status = $7, response_body = $8
			WHERE tenant_id = $1 AND id = $2
		`, r.tenantID, id, status, attempts, nextRetry, lastAttempt, httpStatus, responseBody)
		return err
	})
}

func (r *sharedWebhookRepo) ListDeliveries(ctx context.Context, webhookID string, limit, offset int, filter repository.WebhookDeliveryFilter) ([]*repository.WebhookDelivery, error) {
	args := []any{r.tenantID, webhookID}
	argN := 3
	conditions := []string{"tenant_id = $1", "webhook_id = $2"}

	if !filter.From.IsZero() {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argN))
		args = append(args, filter.From.UTC())
		argN++
	}
	if !filter.To.IsZero() {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argN))
		args = append(args, filter.To.UTC())
		argN++
	}
	if filter.Result != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argN))
		args = append(args, filter.Result)
		argN++
	}
	if filter.Event != "" {
		conditions = append(conditions, fmt.Sprintf("event_type = $%d", argN))
		args = append(args, filter.Event)
		argN++
	}

	args = append(args, limit+1, offset)
	query := fmt.Sprintf(`
		SELECT id, webhook_id, event_type, payload, status,
		       attempts, last_attempt, next_retry, http_status, response_body, created_at
		FROM webhook_delivery
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, strings.Join(conditions, " AND "), argN, argN+1)

	rows, err := r.pool.Query(ctx, query, args...)
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
	pool     *pgxpool.Pool
	tenantID uuid.UUID
}

func (r *sharedInvitationRepo) Create(ctx context.Context, in repository.CreateInvitationInput) (*repository.Invitation, error) {
	var out repository.Invitation
	err := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		const q = `
			INSERT INTO invitation (tenant_id, email, token_hash, invited_by, roles, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING id, tenant_id, email, token_hash, status, invited_by, roles,
			          expires_at, accepted_at, created_at, updated_at
		`
		return tx.QueryRow(ctx, q, r.tenantID, in.Email, in.TokenHash, in.InvitedByID, in.Roles, in.ExpiresAt).Scan(
			&out.ID, &out.TenantID, &out.Email, &out.TokenHash, &out.Status,
			&out.InvitedByID, &out.Roles, &out.ExpiresAt, &out.AcceptedAt,
			&out.CreatedAt, &out.UpdatedAt,
		)
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *sharedInvitationRepo) GetByTokenHash(ctx context.Context, _, hash string) (*repository.Invitation, error) {
	const q = `
		SELECT id, tenant_id, email, token_hash, status, invited_by, roles,
		       expires_at, accepted_at, created_at, updated_at
		FROM invitation
		WHERE tenant_id = $1 AND token_hash = $2
	`
	var out repository.Invitation
	err := r.pool.QueryRow(ctx, q, r.tenantID, hash).Scan(
		&out.ID, &out.TenantID, &out.Email, &out.TokenHash, &out.Status,
		&out.InvitedByID, &out.Roles, &out.ExpiresAt, &out.AcceptedAt,
		&out.CreatedAt, &out.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *sharedInvitationRepo) GetByID(ctx context.Context, _, id string) (*repository.Invitation, error) {
	const q = `
		SELECT id, tenant_id, email, token_hash, status, invited_by, roles,
		       expires_at, accepted_at, created_at, updated_at
		FROM invitation
		WHERE tenant_id = $1 AND id = $2
	`
	var out repository.Invitation
	err := r.pool.QueryRow(ctx, q, r.tenantID, id).Scan(
		&out.ID, &out.TenantID, &out.Email, &out.TokenHash, &out.Status,
		&out.InvitedByID, &out.Roles, &out.ExpiresAt, &out.AcceptedAt,
		&out.CreatedAt, &out.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *sharedInvitationRepo) List(ctx context.Context, _ string, status *repository.InvitationStatus, limit, offset int) ([]repository.Invitation, error) {
	q := `
		SELECT id, tenant_id, email, token_hash, status, invited_by, roles,
		       expires_at, accepted_at, created_at, updated_at
		FROM invitation
		WHERE tenant_id = $1
	`
	args := []any{r.tenantID}
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
			&item.ID, &item.TenantID, &item.Email, &item.TokenHash, &item.Status,
			&item.InvitedByID, &item.Roles, &item.ExpiresAt, &item.AcceptedAt,
			&item.CreatedAt, &item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *sharedInvitationRepo) UpdateStatus(ctx context.Context, _, id string, newStatus repository.InvitationStatus, acceptedAt *time.Time) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE invitation
			SET status = $3, accepted_at = $4, updated_at = NOW()
			WHERE tenant_id = $1 AND id = $2 AND status = 'pending'
		`, r.tenantID, id, string(newStatus), acceptedAt)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrInvitationNotPending
		}
		return nil
	})
}

func (r *sharedInvitationRepo) Delete(ctx context.Context, _, id string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM invitation WHERE tenant_id = $1 AND id = $2`, r.tenantID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

// ─── sharedWebAuthnRepo ──────────────────────────────────────────

type sharedWebAuthnRepo struct {
	pool     *pgxpool.Pool
	tenantID uuid.UUID
}

func (r *sharedWebAuthnRepo) Create(ctx context.Context, _ string, cred repository.WebAuthnCredential) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO webauthn_credential
				(tenant_id, user_id, credential_id, public_key, aaguid, sign_count,
				 transports, user_verified, backup_eligible, backup_state, name)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		`, r.tenantID, cred.UserID, cred.CredentialID, cred.PublicKey, cred.AAGUID,
			int64(cred.SignCount), cred.Transports, cred.UserVerified, cred.BackupEligible,
			cred.BackupState, cred.Name)
		return err
	})
}

func (r *sharedWebAuthnRepo) GetByUserID(ctx context.Context, _, userID string) ([]repository.WebAuthnCredential, error) {
	const q = `
		SELECT id, tenant_id, user_id, credential_id, public_key, aaguid, sign_count,
		       transports, user_verified, backup_eligible, backup_state, name,
		       created_at, last_used_at
		FROM webauthn_credential
		WHERE tenant_id = $1 AND user_id = $2
		ORDER BY created_at ASC
	`
	rows, err := r.pool.Query(ctx, q, r.tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]repository.WebAuthnCredential, 0)
	for rows.Next() {
		item, err := scanSharedWebAuthnCredential(rows)
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
		WHERE tenant_id = $1 AND credential_id = $2
	`
	rows, err := r.pool.Query(ctx, q, r.tenantID, credID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, repository.ErrNotFound
	}
	item, err := scanSharedWebAuthnCredential(rows)
	if err != nil {
		return nil, err
	}
	return &item, nil
}

func (r *sharedWebAuthnRepo) UpdateSignCount(ctx context.Context, _ string, credID []byte, newCount uint32) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE webauthn_credential SET sign_count = $3 WHERE tenant_id = $1 AND credential_id = $2`,
			r.tenantID, credID, int64(newCount))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *sharedWebAuthnRepo) UpdateLastUsed(ctx context.Context, _ string, credID []byte) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE webauthn_credential SET last_used_at = NOW() WHERE tenant_id = $1 AND credential_id = $2`,
			r.tenantID, credID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *sharedWebAuthnRepo) Delete(ctx context.Context, _, id string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM webauthn_credential WHERE tenant_id = $1 AND id = $2`,
			r.tenantID, id)
		return err
	})
}

func scanSharedWebAuthnCredential(row pgx.Row) (repository.WebAuthnCredential, error) {
	var (
		item      repository.WebAuthnCredential
		signCount int64
		lastUsed  *time.Time
	)
	err := row.Scan(
		&item.ID, &item.TenantID, &item.UserID, &item.CredentialID,
		&item.PublicKey, &item.AAGUID, &signCount,
		&item.Transports, &item.UserVerified, &item.BackupEligible, &item.BackupState,
		&item.Name, &item.CreatedAt, &lastUsed,
	)
	if err != nil {
		return repository.WebAuthnCredential{}, err
	}
	item.SignCount = uint32(signCount)
	item.LastUsedAt = lastUsed
	return item, nil
}

// ─── sharedAuditRepo ─────────────────────────────────────────────

type sharedAuditRepo struct {
	pool     *pgxpool.Pool
	tenantID uuid.UUID
}

func (r *sharedAuditRepo) InsertBatch(ctx context.Context, events []audit.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		const stmt = `
			INSERT INTO audit_log (
				id, tenant_id, event_type, actor_id, actor_type,
				target_id, target_type, ip_address, user_agent,
				metadata, result, created_at
			) VALUES (
				$1, $2, $3, $4, $5,
				$6, $7, $8::inet, $9,
				$10, $11, $12
			)
		`

		batch := &pgx.Batch{}
		for _, e := range events {
			meta, err := json.Marshal(e.Metadata)
			if err != nil {
				log.Printf("[WARN] pg_shared: audit_log: json.Marshal metadata for event %s: %v - storing NULL", e.ID, err)
				meta = []byte("{}")
			}
			if meta == nil {
				meta = []byte("{}")
			}

			ip := sanitizeIP(e.IPAddress)

			batch.Queue(stmt,
				e.ID,
				r.tenantID,
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
		}

		br := tx.SendBatch(ctx, batch)
		for range events {
			if _, err := br.Exec(); err != nil {
				br.Close()
				return fmt.Errorf("pg_shared audit insert batch exec: %w", err)
			}
		}
		return br.Close()
	})
}

func (r *sharedAuditRepo) List(ctx context.Context, filter repository.AuditFilter) ([]audit.AuditEvent, int64, error) {
	var (
		where []string
		args  []any
		idx   = 1
	)

	// Always filter by tenant
	where = append(where, fmt.Sprintf("tenant_id = $%d", idx))
	args = append(args, r.tenantID)
	idx++

	if filter.EventType != "" {
		where = append(where, fmt.Sprintf("event_type = $%d", idx))
		args = append(args, filter.EventType)
		idx++
	}
	if filter.ActorID != "" {
		where = append(where, fmt.Sprintf("actor_id = $%d", idx))
		args = append(args, filter.ActorID)
		idx++
	}
	if filter.TargetID != "" {
		where = append(where, fmt.Sprintf("target_id = $%d", idx))
		args = append(args, filter.TargetID)
		idx++
	}
	if filter.Result != "" {
		where = append(where, fmt.Sprintf("result = $%d", idx))
		args = append(args, filter.Result)
		idx++
	}
	if !filter.From.IsZero() {
		where = append(where, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, filter.From)
		idx++
	}
	if !filter.To.IsZero() {
		where = append(where, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, filter.To)
		idx++
	}

	whereClause := "WHERE " + strings.Join(where, " AND ")

	// Count
	var total int64
	if err := r.pool.QueryRow(ctx, "SELECT COUNT(*) FROM audit_log "+whereClause, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("pg_shared audit count: %w", err)
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
		       target_id, target_type, ip_address::text, user_agent,
		       metadata, result, created_at
		FROM audit_log %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, idx, idx+1)
	args = append(args, limit, offset)

	rows, err := r.pool.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("pg_shared audit list: %w", err)
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
			return nil, 0, fmt.Errorf("pg_shared audit scan: %w", err)
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
				log.Printf("[WARN] pg_shared: audit_log: json.Unmarshal metadata for event %s: %v - using empty metadata", e.ID, err)
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
		       target_id, target_type, ip_address::text, user_agent,
		       metadata, result, created_at
		FROM audit_log WHERE tenant_id = $1 AND id = $2
	`

	var e audit.AuditEvent
	var eventType string
	var actorID, targetID, targetType, ipAddr, ua *string
	var metaBytes []byte

	err := r.pool.QueryRow(ctx, q, r.tenantID, id).Scan(
		&e.ID, &eventType, &actorID, &e.ActorType,
		&targetID, &targetType, &ipAddr, &ua,
		&metaBytes, &e.Result, &e.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("pg_shared audit get by id: %w", err)
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
			log.Printf("[WARN] pg_shared audit: json.Unmarshal metadata for event %s: %v", e.ID, err)
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

		var n int64
		err := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `
				DELETE FROM audit_log
				WHERE tenant_id = $1 AND id IN (
					SELECT id FROM audit_log
					WHERE tenant_id = $1 AND created_at < $2
					LIMIT $3
				)
			`, r.tenantID, before, batchSize)
			if err != nil {
				return err
			}
			n = tag.RowsAffected()
			return nil
		})
		if err != nil {
			return total, fmt.Errorf("pg_shared audit purge: %w", err)
		}
		total += n
		if n < int64(batchSize) {
			return total, nil
		}
	}
}
