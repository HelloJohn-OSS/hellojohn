package helpers

import (
	"context"
	"errors"

	"github.com/dropDatabas3/hellojohn/internal/store"
)

type ctxKey string

const (
	ctxTenantIDKey   ctxKey = "tenant_id"
	ctxTenantSlugKey ctxKey = "tenant_slug"
	ctxUserIDKey     ctxKey = "user_id"
	ctxTenantDataKey ctxKey = "tenant_data_access"
)

// TenantUser representa un par (tenant, user) resuelto por middleware.
type TenantUser struct {
	TenantID string
	UserID   string
}

// ─── Tenant Helpers ───

func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, ctxTenantIDKey, tenantID)
}

func GetTenantID(ctx context.Context) string {
	if v := ctx.Value(ctxTenantIDKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func WithTenantSlug(ctx context.Context, tenantSlug string) context.Context {
	return context.WithValue(ctx, ctxTenantSlugKey, tenantSlug)
}

func GetTenantSlug(ctx context.Context) string {
	if v := ctx.Value(ctxTenantSlugKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// ─── Store V2 Integration ───

// WithTenantDataAccess inyecta el acceso a datos del tenant en el contexto.
func WithTenantDataAccess(ctx context.Context, tda store.TenantDataAccess) context.Context {
	ctx = WithTenantID(ctx, tda.ID())
	ctx = WithTenantSlug(ctx, tda.Slug())
	return context.WithValue(ctx, ctxTenantDataKey, tda)
}

// GetTenantDataAccess obtiene el acceso a datos del tenant del contexto.
// Retorna error si no está presente (middleware no ejecutado).
func GetTenantDataAccess(ctx context.Context) (store.TenantDataAccess, error) {
	if v := ctx.Value(ctxTenantDataKey); v != nil {
		if tda, ok := v.(store.TenantDataAccess); ok {
			return tda, nil
		}
	}
	return nil, errors.New("helpers: no tenant data access in context")
}

// GetTenantDataAccessOrPanic obtiene el acceso a datos o entra en pánico.
// Útil cuando estamos seguros de que el middleware se ejecutó.
func GetTenantDataAccessOrPanic(ctx context.Context) store.TenantDataAccess {
	tda, err := GetTenantDataAccess(ctx)
	if err != nil {
		panic(err)
	}
	return tda
}

// ─── User Helpers ───

func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, ctxUserIDKey, userID)
}

func GetUserID(ctx context.Context) string {
	if v := ctx.Value(ctxUserIDKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func WithTenantUser(ctx context.Context, tu TenantUser) context.Context {
	ctx = WithTenantID(ctx, tu.TenantID)
	ctx = WithUserID(ctx, tu.UserID)
	return ctx
}

func GetTenantUser(ctx context.Context) (TenantUser, bool) {
	tu := TenantUser{TenantID: GetTenantID(ctx), UserID: GetUserID(ctx)}
	if tu.TenantID == "" || tu.UserID == "" {
		return TenantUser{}, false
	}
	return tu, true
}
