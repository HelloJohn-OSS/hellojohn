package repository

import (
	"context"
	"time"
)

// MigrationJob representa un job de migración de datos entre instancias.
type MigrationJob struct {
	ID          string
	TenantID    string
	Type        string    // "gdp_to_isolated" | "instance_to_instance"
	Status      string    // "pending" | "running" | "completed" | "failed"
	ProgressPct int
	SourceInfo  string
	TargetInfo  string
	Error       string
	StartedAt   time.Time
	CompletedAt *time.Time
	CreatedAt   time.Time
}

// MigrationJobRepository gestiona los jobs de migración.
type MigrationJobRepository interface {
	Create(ctx context.Context, job MigrationJob) error
	GetByID(ctx context.Context, id string) (*MigrationJob, error)
	ListByTenant(ctx context.Context, tenantID string) ([]MigrationJob, error)
	UpdateProgress(ctx context.Context, id string, pct int) error
	Complete(ctx context.Context, id string) error
	Fail(ctx context.Context, id, errMsg string) error
}
