// Package pg_shared implements the PostgreSQL adapter with logical tenant isolation.
// Uses a single shared DB for multiple tenants, isolating them via tenant_id columns + RLS.
package pg_shared

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

func init() {
	store.RegisterAdapter(&pgSharedAdapter{})
}

// pgSharedAdapter implements store.Adapter for the Global Data Plane.
type pgSharedAdapter struct{}

func (a *pgSharedAdapter) Name() string { return "pg_shared" }

func (a *pgSharedAdapter) Connect(ctx context.Context, cfg store.AdapterConfig) (store.AdapterConnection, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("pg_shared: parse DSN: %w", err)
	}

	// Pool larger than isolated: one pool serves all tenants.
	if cfg.MaxOpenConns > 0 {
		poolCfg.MaxConns = int32(cfg.MaxOpenConns)
	} else {
		poolCfg.MaxConns = 25
	}
	if cfg.MaxIdleConns > 0 {
		poolCfg.MinConns = int32(cfg.MaxIdleConns)
	} else {
		poolCfg.MinConns = 5
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("pg_shared: create pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pg_shared: ping failed: %w", err)
	}

	return &pgSharedBaseConn{pool: pool}, nil
}

// ─── pgSharedBaseConn ─────────────────────────────────────────────

// pgSharedBaseConn holds the shared pool but has NO tenant context.
// Must be scoped with ForTenant() before using repos.
// Implements store.TenantScopedConnection.
type pgSharedBaseConn struct {
	pool *pgxpool.Pool
}

func (c *pgSharedBaseConn) Name() string                   { return "pg_shared" }
func (c *pgSharedBaseConn) Ping(ctx context.Context) error { return c.pool.Ping(ctx) }
func (c *pgSharedBaseConn) Close() error                   { c.pool.Close(); return nil }

// ForTenant returns a connection with a fixed tenantID for all repos.
// Implements store.TenantScopedConnection.
func (c *pgSharedBaseConn) ForTenant(tenantID uuid.UUID) store.AdapterConnection {
	return &pgSharedTenantConn{pool: c.pool, tenantID: tenantID}
}

// GetMigrationExecutor implements store.MigratableConnection.
func (c *pgSharedBaseConn) GetMigrationExecutor() store.PgxPoolExecutor {
	return &pgxPoolWrapper{pool: c.pool}
}

// Repos on base conn panic — detecting incorrect usage without ForTenant().
func (c *pgSharedBaseConn) Users() repository.UserRepository {
	panic("pg_shared: call ForTenant() first")
}
func (c *pgSharedBaseConn) Tokens() repository.TokenRepository {
	panic("pg_shared: call ForTenant() first")
}
func (c *pgSharedBaseConn) MFA() repository.MFARepository {
	panic("pg_shared: call ForTenant() first")
}
func (c *pgSharedBaseConn) Consents() repository.ConsentRepository {
	panic("pg_shared: call ForTenant() first")
}
func (c *pgSharedBaseConn) RBAC() repository.RBACRepository {
	panic("pg_shared: call ForTenant() first")
}
func (c *pgSharedBaseConn) Schema() repository.SchemaRepository {
	panic("pg_shared: call ForTenant() first")
}
func (c *pgSharedBaseConn) EmailTokens() repository.EmailTokenRepository {
	panic("pg_shared: call ForTenant() first")
}
func (c *pgSharedBaseConn) Identities() repository.IdentityRepository {
	panic("pg_shared: call ForTenant() first")
}
func (c *pgSharedBaseConn) Sessions() repository.SessionRepository {
	panic("pg_shared: call ForTenant() first")
}
func (c *pgSharedBaseConn) Audit() repository.AuditRepository {
	panic("pg_shared: call ForTenant() first")
}
func (c *pgSharedBaseConn) Webhooks() repository.WebhookRepository {
	panic("pg_shared: call ForTenant() first")
}
func (c *pgSharedBaseConn) Invitations() repository.InvitationRepository {
	panic("pg_shared: call ForTenant() first")
}
func (c *pgSharedBaseConn) WebAuthn() repository.WebAuthnRepository {
	panic("pg_shared: call ForTenant() first")
}

// Control Plane repos — not implemented in pg_shared (FS adapter handles these).
func (c *pgSharedBaseConn) Tenants() repository.TenantRepository                       { return nil }
func (c *pgSharedBaseConn) SystemSettings() repository.SystemSettingsRepository        { return nil }
func (c *pgSharedBaseConn) Admins() repository.AdminRepository                         { return nil }
func (c *pgSharedBaseConn) AdminRefreshTokens() repository.AdminRefreshTokenRepository { return nil }
func (c *pgSharedBaseConn) Keys() repository.KeyRepository                             { return nil }
func (c *pgSharedBaseConn) APIKeys() repository.APIKeyRepository                       { return nil }
func (c *pgSharedBaseConn) CloudUsers() repository.CloudUserRepository                 { return nil }
func (c *pgSharedBaseConn) CloudInstances() repository.CloudInstanceRepository         { return nil }

// ─── pgSharedTenantConn ───────────────────────────────────────────

// pgSharedTenantConn is a connection with a fixed tenantID.
// All repos use this tenantID in all queries.
// Close() is a no-op: the pool is shared and must not be closed per-tenant.
type pgSharedTenantConn struct {
	pool     *pgxpool.Pool
	tenantID uuid.UUID
}

func (c *pgSharedTenantConn) Name() string                   { return "pg_shared" }
func (c *pgSharedTenantConn) Ping(ctx context.Context) error { return c.pool.Ping(ctx) }
func (c *pgSharedTenantConn) Close() error                   { return nil } // DO NOT close the shared pool

func (c *pgSharedTenantConn) Users() repository.UserRepository {
	return &sharedUserRepo{pool: c.pool, tenantID: c.tenantID}
}
func (c *pgSharedTenantConn) Tokens() repository.TokenRepository {
	return &sharedTokenRepo{pool: c.pool, tenantID: c.tenantID}
}
func (c *pgSharedTenantConn) MFA() repository.MFARepository {
	return &sharedMFARepo{pool: c.pool, tenantID: c.tenantID}
}
func (c *pgSharedTenantConn) Consents() repository.ConsentRepository {
	return &sharedConsentRepo{pool: c.pool, tenantID: c.tenantID}
}
func (c *pgSharedTenantConn) RBAC() repository.RBACRepository {
	return &sharedRBACRepo{pool: c.pool, tenantID: c.tenantID}
}
func (c *pgSharedTenantConn) Schema() repository.SchemaRepository {
	return &sharedSchemaRepo{pool: c.pool, tenantID: c.tenantID}
}
func (c *pgSharedTenantConn) EmailTokens() repository.EmailTokenRepository {
	return &sharedEmailTokenRepo{pool: c.pool, tenantID: c.tenantID}
}
func (c *pgSharedTenantConn) Identities() repository.IdentityRepository {
	return &sharedIdentityRepo{pool: c.pool, tenantID: c.tenantID}
}
func (c *pgSharedTenantConn) Sessions() repository.SessionRepository {
	return &sharedSessionRepo{pool: c.pool, tenantID: c.tenantID}
}
func (c *pgSharedTenantConn) Audit() repository.AuditRepository {
	return &sharedAuditRepo{pool: c.pool, tenantID: c.tenantID}
}
func (c *pgSharedTenantConn) Webhooks() repository.WebhookRepository {
	return &sharedWebhookRepo{pool: c.pool, tenantID: c.tenantID}
}
func (c *pgSharedTenantConn) Invitations() repository.InvitationRepository {
	return &sharedInvitationRepo{pool: c.pool, tenantID: c.tenantID}
}
func (c *pgSharedTenantConn) WebAuthn() repository.WebAuthnRepository {
	return &sharedWebAuthnRepo{pool: c.pool, tenantID: c.tenantID}
}

// Control Plane repos — not implemented.
func (c *pgSharedTenantConn) Tenants() repository.TenantRepository                       { return nil }
func (c *pgSharedTenantConn) SystemSettings() repository.SystemSettingsRepository        { return nil }
func (c *pgSharedTenantConn) Admins() repository.AdminRepository                         { return nil }
func (c *pgSharedTenantConn) AdminRefreshTokens() repository.AdminRefreshTokenRepository { return nil }
func (c *pgSharedTenantConn) Keys() repository.KeyRepository                             { return nil }
func (c *pgSharedTenantConn) APIKeys() repository.APIKeyRepository                       { return nil }
func (c *pgSharedTenantConn) CloudUsers() repository.CloudUserRepository                 { return nil }
func (c *pgSharedTenantConn) CloudInstances() repository.CloudInstanceRepository         { return nil }

// pgxPoolWrapper adapts pgxpool.Pool to store.PgxPoolExecutor.
type pgxPoolWrapper struct{ pool *pgxpool.Pool }

func (w *pgxPoolWrapper) Exec(ctx context.Context, sql string, args ...any) (interface{ RowsAffected() int64 }, error) {
	return w.pool.Exec(ctx, sql, args...)
}

func (w *pgxPoolWrapper) QueryRow(ctx context.Context, sql string, args ...any) interface{ Scan(dest ...any) error } {
	return w.pool.QueryRow(ctx, sql, args...)
}
