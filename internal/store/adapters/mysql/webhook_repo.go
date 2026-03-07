package mysql

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

func (r *webhookRepo) InsertDelivery(ctx context.Context, delivery *repository.WebhookDelivery) error {
	const query = `
		INSERT INTO webhook_delivery (id, webhook_id, event_type, payload, status, attempts, next_retry, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := r.db.ExecContext(ctx, query,
		delivery.ID, delivery.WebhookID, delivery.EventType, delivery.Payload, delivery.Status,
		delivery.Attempts, delivery.NextRetryAt, delivery.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("mysql: insert webhook delivery: %w", err)
	}
	return nil
}

func (r *webhookRepo) FetchPending(ctx context.Context, limit int) ([]*repository.WebhookDelivery, error) {
	// MySQL 8.0 support FOR UPDATE SKIP LOCKED
	const query = `
		SELECT id, webhook_id, event_type, payload, status, attempts, last_attempt, next_retry, http_status, response_body, created_at
		FROM webhook_delivery
		WHERE status IN ('pending', 'failed') AND next_retry <= NOW(6)
		ORDER BY next_retry ASC
		LIMIT ?
		FOR UPDATE SKIP LOCKED
	`

	rows, err := r.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("mysql: fetch pending webhooks: %w", err)
	}
	defer rows.Close()

	var deliveries []*repository.WebhookDelivery
	for rows.Next() {
		var d repository.WebhookDelivery
		var payloadStr string // Need to scan to string then convert to json.RawMessage if needed

		if err := rows.Scan(
			&d.ID, &d.WebhookID, &d.EventType, &payloadStr, &d.Status, &d.Attempts,
			&d.LastAttemptAt, &d.NextRetryAt, &d.HTTPStatus, &d.ResponseBody, &d.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("mysql: scan webhook delivery: %w", err)
		}
		d.Payload = []byte(payloadStr)
		deliveries = append(deliveries, &d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mysql: rows err fetch pending webhooks: %w", err)
	}

	return deliveries, nil
}

func (r *webhookRepo) UpdateDeliveryStatus(ctx context.Context, id string, status string, attempts int, nextRetry, lastAttempt *time.Time, httpStatus *int, responseBody *string) error {
	const query = `
		UPDATE webhook_delivery SET
			status = ?,
			attempts = ?,
			next_retry = ?,
			last_attempt = ?,
			http_status = ?,
			response_body = ?
		WHERE id = ?
	`
	_, err := r.db.ExecContext(ctx, query, status, attempts, nextRetry, lastAttempt, httpStatus, responseBody, id)
	if err != nil {
		return fmt.Errorf("mysql: update webhook delivery status: %w", err)
	}
	return nil
}

func (r *webhookRepo) ListDeliveries(ctx context.Context, webhookID string, limit, offset int, filter repository.WebhookDeliveryFilter) ([]*repository.WebhookDelivery, error) {
	// MySQL usa ? como placeholder. El orden de args determina el binding.
	args := []any{webhookID}

	var conditions []string
	conditions = append(conditions, "webhook_id = ?")

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

	// limit+1 para has_more
	args = append(args, limit+1, offset)

	where := "WHERE " + strings.Join(conditions, " AND ")
	query := fmt.Sprintf(`
		SELECT id, webhook_id, event_type, payload, status,
		       attempts, last_attempt, next_retry, http_status, response_body, created_at
		FROM webhook_delivery
		%s
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`, where)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("mysql: list webhook deliveries: %w", err)
	}
	defer rows.Close()

	var deliveries []*repository.WebhookDelivery
	for rows.Next() {
		d := &repository.WebhookDelivery{}
		var payload string // MySQL retorna JSON como string
		if err := rows.Scan(
			&d.ID, &d.WebhookID, &d.EventType, &payload,
			&d.Status, &d.Attempts, &d.LastAttemptAt, &d.NextRetryAt,
			&d.HTTPStatus, &d.ResponseBody, &d.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("mysql: scan list webhook delivery: %w", err)
		}
		d.Payload = json.RawMessage([]byte(payload))
		deliveries = append(deliveries, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("mysql: rows err list webhook deliveries: %w", err)
	}

	return deliveries, nil
}
