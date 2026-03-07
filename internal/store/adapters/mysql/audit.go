// Package mysql implementa AuditRepository para MySQL.
package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// Verificar que implementa la interfaz
var _ repository.AuditRepository = (*auditRepo)(nil)

// auditRepo implementa repository.AuditRepository para MySQL.
type auditRepo struct {
	db *sql.DB
}

// InsertBatch inserta múltiples eventos de auditoría en un solo statement.
func (r *auditRepo) InsertBatch(ctx context.Context, events []audit.AuditEvent) error {
	if len(events) == 0 {
		return nil
	}

	const cols = `(id, event_type, actor_id, actor_type,
		target_id, target_type, ip_address, user_agent,
		metadata, result, created_at)`

	placeholders := make([]string, 0, len(events))
	args := make([]any, 0, len(events)*11)

	for _, e := range events {
		placeholders = append(placeholders, "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")

		meta, err := json.Marshal(e.Metadata)
		if err != nil {
			log.Printf("WARN: audit: json.Marshal metadata for event %s: %v (using empty object)", e.ID, err)
			meta = []byte("{}")
		}
		if meta == nil {
			meta = []byte("{}")
		}

		args = append(args,
			e.ID,
			string(e.Type),
			nullIfEmpty(e.ActorID),
			e.ActorType,
			nullIfEmpty(e.TargetID),
			nullIfEmpty(e.TargetType),
			sanitizeIP(e.IPAddress),
			nullIfEmpty(e.UserAgent),
			string(meta),
			e.Result,
			e.CreatedAt,
		)
	}

	query := "INSERT INTO audit_log " + cols + " VALUES " + strings.Join(placeholders, ", ")

	_, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("audit insert batch: %w", err)
	}

	return nil
}

// List retorna eventos de auditoría filtrados con paginación.
func (r *auditRepo) List(ctx context.Context, filter repository.AuditFilter) ([]audit.AuditEvent, int64, error) {
	var (
		where []string
		args  []any
	)

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

	whereClause := ""
	if len(where) > 0 {
		whereClause = "WHERE " + strings.Join(where, " AND ")
	}

	// Count
	countQuery := "SELECT COUNT(*) FROM audit_log " + whereClause
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
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
		       target_id, target_type, ip_address, user_agent,
		       metadata, result, created_at
		FROM audit_log %s
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`, whereClause)
	dataArgs := append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, dataQuery, dataArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("audit list: %w", err)
	}
	defer rows.Close()

	var events []audit.AuditEvent
	for rows.Next() {
		var e audit.AuditEvent
		var eventType string
		var actorID, targetID, targetType, ipAddr, ua sql.NullString
		var metaStr sql.NullString

		if err := rows.Scan(
			&e.ID, &eventType, &actorID, &e.ActorType,
			&targetID, &targetType, &ipAddr, &ua,
			&metaStr, &e.Result, &e.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("audit scan: %w", err)
		}

		e.Type = audit.EventType(eventType)
		if actorID.Valid {
			e.ActorID = actorID.String
		}
		if targetID.Valid {
			e.TargetID = targetID.String
		}
		if targetType.Valid {
			e.TargetType = targetType.String
		}
		if ipAddr.Valid {
			e.IPAddress = ipAddr.String
		}
		if ua.Valid {
			e.UserAgent = ua.String
		}
		if metaStr.Valid && metaStr.String != "" {
			if err := json.Unmarshal([]byte(metaStr.String), &e.Metadata); err != nil {
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
		       target_id, target_type, ip_address, user_agent,
		       metadata, result, created_at
		FROM audit_log WHERE id = ?
	`

	var e audit.AuditEvent
	var eventType string
	var actorID, targetID, targetType, ipAddr, ua sql.NullString
	var metaStr sql.NullString

	err := r.db.QueryRowContext(ctx, q, id).Scan(
		&e.ID, &eventType, &actorID, &e.ActorType,
		&targetID, &targetType, &ipAddr, &ua,
		&metaStr, &e.Result, &e.CreatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("audit get by id: %w", err)
	}

	e.Type = audit.EventType(eventType)
	if actorID.Valid {
		e.ActorID = actorID.String
	}
	if targetID.Valid {
		e.TargetID = targetID.String
	}
	if targetType.Valid {
		e.TargetType = targetType.String
	}
	if ipAddr.Valid {
		e.IPAddress = ipAddr.String
	}
	if ua.Valid {
		e.UserAgent = ua.String
	}
	if metaStr.Valid && metaStr.String != "" {
		if err := json.Unmarshal([]byte(metaStr.String), &e.Metadata); err != nil {
			log.Printf("WARN: audit: json.Unmarshal metadata for event %s: %v", e.ID, err)
			e.Metadata = map[string]any{"_metadata_parse_error": err.Error()}
		}
	}

	return &e, nil
}

// Purge elimina eventos anteriores a la fecha dada.
func (r *auditRepo) Purge(ctx context.Context, before time.Time) (int64, error) {
	return purgeInBatches(ctx, 1000, func(ctx context.Context, limit int) (int64, error) {
		result, err := r.db.ExecContext(ctx, "DELETE FROM audit_log WHERE created_at < ? LIMIT ?", before, limit)
		if err != nil {
			return 0, fmt.Errorf("audit purge batch: %w", err)
		}
		n, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("audit purge batch rows: %w", err)
		}
		return n, nil
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

// sanitizeIP validates and normalizes a single IP.
// Invalid values are persisted as SQL NULL.
func sanitizeIP(raw string) any {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	// If value comes from X-Forwarded-For, keep only the first hop.
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

	log.Printf("WARN: audit: invalid IP %q, storing as NULL", raw)
	return nil
}
