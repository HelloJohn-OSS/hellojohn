package audit

import (
	"context"
	"errors"
	"log"
	"time"
)

// TenantAuditRepo provides access to an AuditRepository for a specific tenant.
// This matches the DAL.ForTenant() → TDA.Audit() pattern without importing store directly.
type TenantAuditRepo interface {
	InsertBatch(ctx context.Context, events []AuditEvent) error
}

// TenantRepoResolver resolves a tenant ID to its AuditRepository.
// Implemented by a thin wrapper around DAL.ForTenant(tenantID).Audit().
type TenantRepoResolver func(ctx context.Context, tenantID string) (TenantAuditRepo, error)

// DBWriter implements Writer by persisting events to tenant-specific databases.
// Events are grouped by TenantID before dispatching to each tenant's repository.
type DBWriter struct {
	resolve TenantRepoResolver
	logger  *log.Logger
	// maxRetries is the number of additional attempts after the first write try.
	maxRetries int
	// retryDelay is the base delay between retries.
	retryDelay time.Duration
	// deadLetter receives batches that failed persistence after retries.
	deadLetter Writer
}

// NewDBWriter creates a DBWriter with the given resolver.
func NewDBWriter(resolve TenantRepoResolver, logger *log.Logger) *DBWriter {
	return &DBWriter{
		resolve:    resolve,
		logger:     logger,
		maxRetries: 2,
		retryDelay: 100 * time.Millisecond,
	}
}

// SetRetryPolicy sets retry behavior for tenant DB writes.
// maxRetries is the number of retries after the initial attempt.
func (w *DBWriter) SetRetryPolicy(maxRetries int, retryDelay time.Duration) {
	if maxRetries < 0 {
		maxRetries = 0
	}
	if retryDelay < 0 {
		retryDelay = 0
	}
	w.maxRetries = maxRetries
	w.retryDelay = retryDelay
}

// SetDeadLetterWriter configures a fallback writer used when a tenant batch
// cannot be persisted after retries.
func (w *DBWriter) SetDeadLetterWriter(deadLetter Writer) {
	w.deadLetter = deadLetter
}

// ControlPlaneTenantID is a sentinel value for events that originate from the
// control-plane (e.g. admin login) and have no real tenant database.
// DBWriter skips these events without error; StdoutWriter still captures them.
const ControlPlaneTenantID = "system"

// Write groups events by TenantID and inserts each batch into the corresponding tenant DB.
// Errors on individual tenants are logged but do not prevent other tenants from being written.
// Events with TenantID == ControlPlaneTenantID are silently skipped (logged at debug level only).
func (w *DBWriter) Write(ctx context.Context, events []AuditEvent) error {
	// Group by tenant
	byTenant := make(map[string][]AuditEvent, 4)
	for _, e := range events {
		byTenant[e.TenantID] = append(byTenant[e.TenantID], e)
	}

	var firstErr error
	for tenantID, batch := range byTenant {
		// Control-plane events have no tenant DB — skip gracefully.
		if tenantID == ControlPlaneTenantID {
			if w.logger != nil {
				w.logger.Printf("audit: skipping %d control-plane event(s) (tenant %q has no DB)", len(batch), tenantID)
			}
			continue
		}

		if err := w.writeBatchWithRetry(ctx, tenantID, batch); err != nil {
			if w.logger != nil {
				w.logger.Printf("audit: persist tenant %q failed after retries: %v", tenantID, err)
			}
			if firstErr == nil {
				firstErr = err
			}
			if w.deadLetter != nil {
				if dlErr := w.deadLetter.Write(ctx, batch); dlErr != nil {
					if w.logger != nil {
						w.logger.Printf("audit: dead-letter write failed for tenant %q: %v (dropping %d events)", tenantID, dlErr, len(batch))
					}
					if firstErr == nil {
						firstErr = dlErr
					}
				} else if w.logger != nil {
					w.logger.Printf("audit: routed %d event(s) for tenant %q to dead-letter writer", len(batch), tenantID)
				}
			} else if w.logger != nil {
				w.logger.Printf("audit: dropping %d event(s) for tenant %q (no dead-letter writer configured)", len(batch), tenantID)
			}
		}
	}

	return firstErr
}

func (w *DBWriter) writeBatchWithRetry(ctx context.Context, tenantID string, batch []AuditEvent) error {
	attempts := w.maxRetries + 1
	var lastErr error

	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 && w.retryDelay > 0 {
			backoff := time.Duration(attempt-1) * w.retryDelay
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}

		repo, err := w.resolve(ctx, tenantID)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}

		if err := repo.InsertBatch(ctx, batch); err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue
		}

		return nil
	}

	if lastErr == nil {
		lastErr = errors.New("audit db writer: write failed with unknown error")
	}
	return lastErr
}
