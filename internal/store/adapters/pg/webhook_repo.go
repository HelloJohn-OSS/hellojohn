package pg

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/jackc/pgx/v5/pgxpool"
)

type webhookRepo struct {
	pool *pgxpool.Pool
}

func (r *webhookRepo) InsertDelivery(ctx context.Context, delivery *repository.WebhookDelivery) error {
	const query = `
		INSERT INTO webhook_delivery (id, webhook_id, event_type, payload, status, attempts, next_retry, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := r.pool.Exec(ctx, query,
		delivery.ID, delivery.WebhookID, delivery.EventType, delivery.Payload, delivery.Status,
		delivery.Attempts, delivery.NextRetryAt, delivery.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("pg: insert webhook delivery: %w", err)
	}
	return nil
}

func (r *webhookRepo) FetchPending(ctx context.Context, limit int) ([]*repository.WebhookDelivery, error) {
	const query = `
		SELECT id, webhook_id, event_type, payload, status, attempts, last_attempt, next_retry, http_status, response_body, created_at
		FROM webhook_delivery
		WHERE status IN ('pending', 'failed') AND next_retry <= NOW()
		ORDER BY next_retry ASC
		LIMIT $1
		FOR UPDATE SKIP LOCKED
	`

	rows, err := r.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("pg: fetch pending webhooks: %w", err)
	}
	defer rows.Close()

	var deliveries []*repository.WebhookDelivery
	for rows.Next() {
		var d repository.WebhookDelivery
		if err := rows.Scan(
			&d.ID, &d.WebhookID, &d.EventType, &d.Payload, &d.Status, &d.Attempts,
			&d.LastAttemptAt, &d.NextRetryAt, &d.HTTPStatus, &d.ResponseBody, &d.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("pg: scan webhook delivery: %w", err)
		}
		deliveries = append(deliveries, &d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pg: rows err fetch pending webhooks: %w", err)
	}

	return deliveries, nil
}

func (r *webhookRepo) UpdateDeliveryStatus(ctx context.Context, id string, status string, attempts int, nextRetry, lastAttempt *time.Time, httpStatus *int, responseBody *string) error {
	const query = `
		UPDATE webhook_delivery SET
			status = $2,
			attempts = $3,
			next_retry = $4,
			last_attempt = $5,
			http_status = $6,
			response_body = $7
		WHERE id = $1
	`
	_, err := r.pool.Exec(ctx, query, id, status, attempts, nextRetry, lastAttempt, httpStatus, responseBody)
	if err != nil {
		return fmt.Errorf("pg: update webhook delivery status: %w", err)
	}
	return nil
}

func buildListDeliveriesQuery(webhookID string, limit, offset int, filter repository.WebhookDeliveryFilter) (string, []any) {
	// Build dynamic SQL with safe $N placeholders.
	// Never interpolate user input directly in SQL strings.
	args := []any{webhookID}
	argN := 2 // $1 is already webhookID

	conditions := []string{"webhook_id = $1"}

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

	// Request limit+1 rows to derive has_more without COUNT(*).
	args = append(args, limit+1, offset)
	limitPlaceholder := fmt.Sprintf("$%d", argN)
	offsetPlaceholder := fmt.Sprintf("$%d", argN+1)

	where := "WHERE " + strings.Join(conditions, " AND ")
	query := fmt.Sprintf(`
		SELECT id, webhook_id, event_type, payload, status,
		       attempts, last_attempt, next_retry, http_status, response_body, created_at
		FROM webhook_delivery
		%s
		ORDER BY created_at DESC
		LIMIT %s OFFSET %s
	`, where, limitPlaceholder, offsetPlaceholder)

	return query, args
}

func (r *webhookRepo) ListDeliveries(ctx context.Context, webhookID string, limit, offset int, filter repository.WebhookDeliveryFilter) ([]*repository.WebhookDelivery, error) {
	query, args := buildListDeliveriesQuery(webhookID, limit, offset, filter)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("pg: list webhook deliveries: %w", err)
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
			return nil, fmt.Errorf("pg: scan list webhook delivery: %w", err)
		}
		d.Payload = json.RawMessage(payload)
		deliveries = append(deliveries, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pg: rows err list webhook deliveries: %w", err)
	}

	return deliveries, nil
}
