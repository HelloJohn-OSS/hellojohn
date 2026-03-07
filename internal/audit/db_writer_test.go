package audit

import (
	"context"
	"errors"
	"sync"
	"testing"
)

type dbRepoRecorder struct {
	mu          sync.Mutex
	calls       int
	failForCall int
	failErr     error
	written     []AuditEvent
}

func (r *dbRepoRecorder) InsertBatch(_ context.Context, events []AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.calls <= r.failForCall {
		if r.failErr != nil {
			return r.failErr
		}
		return errors.New("forced insert failure")
	}
	r.written = append(r.written, events...)
	return nil
}

func (r *dbRepoRecorder) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

type deadLetterRecorder struct {
	mu       sync.Mutex
	events   []AuditEvent
	writeErr error
}

func (r *deadLetterRecorder) Write(_ context.Context, events []AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.writeErr != nil {
		return r.writeErr
	}
	r.events = append(r.events, events...)
	return nil
}

func (r *deadLetterRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

func TestDBWriter_RetriesAndSucceeds(t *testing.T) {
	t.Parallel()

	repo := &dbRepoRecorder{
		failForCall: 2,
		failErr:     errors.New("transient db error"),
	}
	w := NewDBWriter(func(context.Context, string) (TenantAuditRepo, error) {
		return repo, nil
	}, nil)
	w.SetRetryPolicy(2, 0)

	err := w.Write(context.Background(), []AuditEvent{
		NewEvent(EventLogin, "tenant-a"),
	})
	if err != nil {
		t.Fatalf("expected write success after retries, got error: %v", err)
	}
	if got := repo.callCount(); got != 3 {
		t.Fatalf("expected 3 insert attempts, got %d", got)
	}
}

func TestDBWriter_ResolveFailureRoutesToDeadLetter(t *testing.T) {
	t.Parallel()

	deadLetter := &deadLetterRecorder{}
	w := NewDBWriter(func(context.Context, string) (TenantAuditRepo, error) {
		return nil, errors.New("tenant has no database")
	}, nil)
	w.SetRetryPolicy(1, 0)
	w.SetDeadLetterWriter(deadLetter)

	err := w.Write(context.Background(), []AuditEvent{
		NewEvent(EventClientUpdated, "tenant-no-db"),
	})
	if err == nil {
		t.Fatalf("expected write error when resolve fails")
	}
	if got := deadLetter.count(); got != 1 {
		t.Fatalf("expected 1 event in dead-letter writer, got %d", got)
	}
}

func TestDBWriter_InsertFailureRoutesToDeadLetterAfterRetries(t *testing.T) {
	t.Parallel()

	repo := &dbRepoRecorder{
		failForCall: 3,
		failErr:     errors.New("persistent insert failure"),
	}
	deadLetter := &deadLetterRecorder{}
	w := NewDBWriter(func(context.Context, string) (TenantAuditRepo, error) {
		return repo, nil
	}, nil)
	w.SetRetryPolicy(2, 0)
	w.SetDeadLetterWriter(deadLetter)

	err := w.Write(context.Background(), []AuditEvent{
		NewEvent(EventTenantUpdated, "tenant-a"),
	})
	if err == nil {
		t.Fatalf("expected write error after retries exhausted")
	}
	if got := repo.callCount(); got != 3 {
		t.Fatalf("expected 3 insert attempts, got %d", got)
	}
	if got := deadLetter.count(); got != 1 {
		t.Fatalf("expected 1 dead-letter event, got %d", got)
	}
}

func TestDBWriter_SkipsSystemTenant(t *testing.T) {
	t.Parallel()

	resolveCalls := 0
	w := NewDBWriter(func(context.Context, string) (TenantAuditRepo, error) {
		resolveCalls++
		return nil, errors.New("should not be called for system tenant")
	}, nil)

	if err := w.Write(context.Background(), []AuditEvent{
		NewEvent(EventLoginFailed, ControlPlaneTenantID),
	}); err != nil {
		t.Fatalf("expected nil error for system tenant skip, got %v", err)
	}
	if resolveCalls != 0 {
		t.Fatalf("expected resolver to be skipped for system tenant, got %d call(s)", resolveCalls)
	}
}
