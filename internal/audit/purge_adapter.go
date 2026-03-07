package audit

import (
	"context"
	"time"
)

// PurgeDeps holds the dependencies for the purge adapter.
type PurgeDeps struct {
	// ListTenantsFn returns all tenants with their audit retention config.
	ListTenantsFn func(ctx context.Context) ([]TenantInfo, error)
	// PurgeFn purges audit events for a single tenant older than `before`.
	PurgeFn func(ctx context.Context, tenantSlug string, before time.Time) (int64, error)
}

// purgeAdapter implements TenantLister and TenantPurger via function closures.
type purgeAdapter struct {
	deps PurgeDeps
}

// NewPurgeAdapter creates an adapter that implements TenantLister and TenantPurger.
func NewPurgeAdapter(deps PurgeDeps) (TenantLister, TenantPurger) {
	a := &purgeAdapter{deps: deps}
	return a, a
}

func (a *purgeAdapter) ListTenantsForPurge(ctx context.Context) ([]TenantInfo, error) {
	return a.deps.ListTenantsFn(ctx)
}

func (a *purgeAdapter) PurgeAudit(ctx context.Context, tenantSlug string, before time.Time) (int64, error) {
	return a.deps.PurgeFn(ctx, tenantSlug, before)
}
