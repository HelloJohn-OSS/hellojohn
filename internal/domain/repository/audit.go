package repository

import (
	"context"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
)

// AuditRepository handles persistence of audit log entries.
type AuditRepository interface {
	// InsertBatch writes multiple audit events in a single DB round-trip.
	InsertBatch(ctx context.Context, events []audit.AuditEvent) error

	// List returns audit events matching the filter, plus the total count for pagination.
	List(ctx context.Context, filter AuditFilter) ([]audit.AuditEvent, int64, error)

	// GetByID returns a single audit event by its ID.
	GetByID(ctx context.Context, id string) (*audit.AuditEvent, error)

	// Purge deletes events older than the given time and returns the number deleted.
	Purge(ctx context.Context, before time.Time) (int64, error)
}

// AuditFilter describes query parameters for listing audit events.
type AuditFilter struct {
	EventType string
	ActorID   string
	TargetID  string
	Result    string
	From      time.Time
	To        time.Time
	Limit     int
	Offset    int
}
