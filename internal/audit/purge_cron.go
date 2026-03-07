package audit

import (
	"context"
	"log"
	"sync"
	"time"
)

// TenantInfo holds the minimal info needed for the purge cron.
type TenantInfo struct {
	Slug          string
	RetentionDays int
}

// TenantLister lists all tenants and their audit retention config.
type TenantLister interface {
	ListTenantsForPurge(ctx context.Context) ([]TenantInfo, error)
}

// TenantPurger purges audit events for a single tenant.
type TenantPurger interface {
	PurgeAudit(ctx context.Context, tenantSlug string, before time.Time) (int64, error)
}

// PurgeCron runs periodic audit log purges based on per-tenant retention config.
type PurgeCron struct {
	lister    TenantLister
	purger    TenantPurger
	interval  time.Duration
	stop      chan struct{}
	startOnce sync.Once // guards Start() against spawning duplicate workers
	stopOnce  sync.Once // guards Stop() against double-close panic
	logger    *log.Logger
}

// NewPurgeCron creates a new PurgeCron.
// interval is how often to check (typically 24h).
func NewPurgeCron(lister TenantLister, purger TenantPurger, interval time.Duration, logger *log.Logger) *PurgeCron {
	if logger == nil {
		logger = log.Default()
	}
	return &PurgeCron{
		lister:   lister,
		purger:   purger,
		interval: interval,
		stop:     make(chan struct{}),
		logger:   logger,
	}
}

// Start begins the periodic purge loop in a background goroutine.
func (c *PurgeCron) Start() {
	c.startOnce.Do(func() {
		go c.run()
	})
}

// Stop signals the purge cron to stop. Safe to call multiple times.
func (c *PurgeCron) Stop() {
	c.stopOnce.Do(func() { close(c.stop) })
}

func (c *PurgeCron) run() {
	// Run once immediately at startup, then on ticker.
	c.purgeAll()

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.purgeAll()
		case <-c.stop:
			return
		}
	}
}

func (c *PurgeCron) purgeAll() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tenants, err := c.lister.ListTenantsForPurge(ctx)
	if err != nil {
		c.logger.Printf("[audit-purge] error listing tenants: %v", err)
		return
	}

	for _, t := range tenants {
		if t.RetentionDays <= 0 {
			continue // no auto-purge for this tenant
		}

		before := time.Now().UTC().AddDate(0, 0, -t.RetentionDays)
		deleted, err := c.purger.PurgeAudit(ctx, t.Slug, before)
		if err != nil {
			c.logger.Printf("[audit-purge] tenant=%s error: %v", t.Slug, err)
			continue
		}
		if deleted > 0 {
			c.logger.Printf("[audit-purge] tenant=%s purged %d events older than %dd", t.Slug, deleted, t.RetentionDays)
		}
	}
}
