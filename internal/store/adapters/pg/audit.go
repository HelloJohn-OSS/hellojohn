// Package pg implementa AuditRepository para PostgreSQL.
package pg

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// auditRepo implementa repository.AuditRepository para PostgreSQL.
type auditRepo struct {
	pool *pgxpool.Pool
}

// InsertBatch inserta múltiples eventos de auditoría en una sola transacción.
func (r *auditRepo) InsertBatch(ctx context.Context, events []audit.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("audit insert batch begin: %w", err)
	}
	defer tx.Rollback(ctx)

	const stmt = `
		INSERT INTO audit_log (
			id, event_type, actor_id, actor_type,
			target_id, target_type, ip_address, user_agent,
			metadata, result, created_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6, $7::inet, $8,
			$9, $10, $11
		)
	`

	batch := &pgx.Batch{}
	for _, e := range events {
		meta, err := json.Marshal(e.Metadata)
		if err != nil {
			log.Printf("WARN: audit: json.Marshal metadata for event %s: %v (using empty object)", e.ID, err)
			meta = []byte("{}")
		}
		if meta == nil {
			meta = []byte("{}")
		}

		// Validate IP before passing to PG INET cast — malformed values from
		// X-Forwarded-For would break the entire batch otherwise.
		ip := sanitizeIP(e.IPAddress)

		batch.Queue(stmt,
			e.ID,
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
			return fmt.Errorf("audit insert batch exec: %w", err)
		}
	}
	if err := br.Close(); err != nil {
		return fmt.Errorf("audit insert batch close: %w", err)
	}

	return tx.Commit(ctx)
}

// List retorna eventos de auditoría filtrados con paginación.
func (r *auditRepo) List(ctx context.Context, filter repository.AuditFilter) ([]audit.AuditEvent, int64, error) {
	var (
		where []string
		args  []any
		idx   = 1
	)

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

	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Count
	countQuery := "SELECT COUNT(*) FROM audit_log " + whereClause
	var total int64
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("audit count: %w", err)
	}

	// Defaults
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
		return nil, 0, fmt.Errorf("audit list: %w", err)
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
			return nil, 0, fmt.Errorf("audit scan: %w", err)
		}

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
				log.Printf("WARN: audit: json.Unmarshal metadata for event %s: %v", e.ID, err)
				e.Metadata = map[string]any{"_metadata_parse_error": err.Error()}
			}
		}

		events = append(events, e)
	}

	return events, total, rows.Err()
}

// GetByID returns a single audit event by its ID.
func (r *auditRepo) GetByID(ctx context.Context, id string) (*audit.AuditEvent, error) {
	const q = `
		SELECT id, event_type, actor_id, actor_type,
		       target_id, target_type, ip_address::text, user_agent,
		       metadata, result, created_at
		FROM audit_log WHERE id = $1
	`

	var e audit.AuditEvent
	var eventType string
	var actorID, targetID, targetType, ipAddr, ua *string
	var metaBytes []byte

	err := r.pool.QueryRow(ctx, q, id).Scan(
		&e.ID, &eventType, &actorID, &e.ActorType,
		&targetID, &targetType, &ipAddr, &ua,
		&metaBytes, &e.Result, &e.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("audit get by id: %w", err)
	}

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
			log.Printf("WARN: audit: json.Unmarshal metadata for event %s: %v", e.ID, err)
			e.Metadata = map[string]any{"_metadata_parse_error": err.Error()}
		}
	}

	return &e, nil
}

// Purge elimina eventos anteriores a la fecha dada.
func (r *auditRepo) Purge(ctx context.Context, before time.Time) (int64, error) {
	return purgeInBatches(ctx, 1000, func(ctx context.Context, limit int) (int64, error) {
		tag, err := r.pool.Exec(ctx, `
			DELETE FROM audit_log
			WHERE id IN (
				SELECT id
				FROM audit_log
				WHERE created_at < $1
				LIMIT $2
			)
		`, before, limit)
		if err != nil {
			return 0, fmt.Errorf("audit purge batch: %w", err)
		}
		return tag.RowsAffected(), nil
	})
}

func purgeInBatches(ctx context.Context, batchSize int, deleteBatch func(ctx context.Context, limit int) (int64, error)) (int64, error) {
	if batchSize <= 0 {
		batchSize = 1000
	}

	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}

		n, err := deleteBatch(ctx, batchSize)
		if err != nil {
			return total, err
		}
		total += n

		if n < int64(batchSize) {
			return total, nil
		}
	}
}

// sanitizeIP validates an IP string for safe use in PG INET cast.
// Returns nil (SQL NULL) if the IP is empty or malformed.
func sanitizeIP(raw string) any {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	// If value comes from X-Forwarded-For, keep only the first hop.
	if i := strings.Index(raw, ","); i >= 0 {
		raw = strings.TrimSpace(raw[:i])
	}
	// Strip port if present (e.g. "1.2.3.4:8080")
	host := raw
	if h, _, err := net.SplitHostPort(raw); err == nil {
		host = h
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	log.Printf("WARN: audit: invalid IP %q, storing as NULL", raw)
	return nil
}
