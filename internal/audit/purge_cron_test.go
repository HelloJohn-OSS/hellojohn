package audit

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type fakePurgeLister struct {
	tenants []TenantInfo
}

func (f fakePurgeLister) ListTenantsForPurge(ctx context.Context) ([]TenantInfo, error) {
	return f.tenants, nil
}

type fakePurger struct {
	calls int32
}

func (f *fakePurger) PurgeAudit(ctx context.Context, tenantSlug string, before time.Time) (int64, error) {
	atomic.AddInt32(&f.calls, 1)
	return 0, nil
}

func TestPurgeCron_SkipsTenantsWithNonPositiveRetention(t *testing.T) {
	t.Parallel()

	purger := &fakePurger{}
	c := NewPurgeCron(
		fakePurgeLister{
			tenants: []TenantInfo{
				{Slug: "tenant-no-purge", RetentionDays: 0},
				{Slug: "tenant-active", RetentionDays: 7},
				{Slug: "tenant-negative", RetentionDays: -1},
			},
		},
		purger,
		time.Hour,
		nil,
	)

	c.purgeAll()

	if got := atomic.LoadInt32(&purger.calls); got != 1 {
		t.Fatalf("expected exactly 1 purge call, got %d", got)
	}
}

func TestPurgeCron_Start_IsIdempotent(t *testing.T) {
	t.Parallel()

	purger := &fakePurger{}
	c := NewPurgeCron(
		fakePurgeLister{
			tenants: []TenantInfo{
				{Slug: "tenant-active", RetentionDays: 7},
			},
		},
		purger,
		time.Hour,
		nil,
	)

	c.Start()
	c.Start() // must not spawn a second worker

	deadline := time.Now().Add(250 * time.Millisecond)
	for atomic.LoadInt32(&purger.calls) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	c.Stop()

	if got := atomic.LoadInt32(&purger.calls); got != 1 {
		t.Fatalf("expected exactly 1 purge call from idempotent Start, got %d", got)
	}
}
