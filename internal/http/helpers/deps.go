package helpers

import (
	"context"
	"net/http"

	cp "github.com/dropDatabas3/hellojohn/internal/controlplane"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// RequestDeps contains dependencies available for a request scope.
type RequestDeps struct {
	DAL          store.DataAccessLayer
	ControlPlane cp.Service
	Issuer       *jwtx.Issuer
	// Add other global dependencies here
}

// TenantDeps contains dependencies specific to a resolved tenant.
type TenantDeps struct {
	RequestDeps
	Tenant *repository.Tenant
	TDA    store.TenantDataAccess
}

// contextKey is a unique type for context keys to avoid collisions.
type contextKey string

const (
	depsKey   contextKey = "v2.deps"
	tenantKey contextKey = "v2.tenant"
)

// WithDeps adds global dependencies to the context.
func WithDeps(ctx context.Context, deps RequestDeps) context.Context {
	return context.WithValue(ctx, depsKey, deps)
}

// DepsFrom retrieves dependencies from the context.
func DepsFrom(ctx context.Context) RequestDeps {
	if val, ok := ctx.Value(depsKey).(RequestDeps); ok {
		return val
	}
	return RequestDeps{}
}

// WithTenant adds tenant dependencies to the context.
func WithTenant(ctx context.Context, td TenantDeps) context.Context {
	return context.WithValue(ctx, tenantKey, td)
}

// TenantFrom retrieves tenant dependencies from the context.
func TenantFrom(ctx context.Context) (TenantDeps, bool) {
	val, ok := ctx.Value(tenantKey).(TenantDeps)
	return val, ok
}

// MustTenantDAL retrieves the TenantDataAccess or panics (use only when middleware guarantees tenant).
func MustTenantDAL(r *http.Request) store.TenantDataAccess {
	td, ok := TenantFrom(r.Context())
	if !ok || td.TDA == nil {
		panic("v2: tenant data access required but missing in context")
	}
	return td.TDA
}
