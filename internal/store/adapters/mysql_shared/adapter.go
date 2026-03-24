// Package mysql_shared implements the MySQL adapter with logical tenant isolation.
// Uses a single shared DB for multiple tenants, isolating them via tenant_id columns
// in every query (WHERE tenant_id = ?). NO RLS support — MySQL doesn't have it.
package mysql_shared

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

func init() {
	store.RegisterAdapter(&mysqlSharedAdapter{})
}

// mysqlSharedAdapter implements store.Adapter for the Global Data Plane (MySQL).
type mysqlSharedAdapter struct{}

func (a *mysqlSharedAdapter) Name() string { return "mysql_shared" }

func (a *mysqlSharedAdapter) Connect(ctx context.Context, cfg store.AdapterConfig) (store.AdapterConnection, error) {
	db, err := sql.Open("mysql", cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: open: %w", err)
	}

	// Pool larger than isolated: one pool serves all tenants.
	if cfg.MaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
	} else {
		db.SetMaxOpenConns(25)
	}
	if cfg.MaxIdleConns > 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConns)
	} else {
		db.SetMaxIdleConns(5)
	}
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("mysql_shared: ping failed: %w", err)
	}

	return &mysqlSharedBaseConn{db: db}, nil
}

// ─── mysqlSharedBaseConn ─────────────────────────────────────────

// mysqlSharedBaseConn holds the shared DB but has NO tenant context.
// Must be scoped with ForTenant() before using repos.
// Implements store.TenantScopedConnection, store.SQLDBConnection, store.MigratableConnection.
type mysqlSharedBaseConn struct {
	db *sql.DB
}

func (c *mysqlSharedBaseConn) Name() string                   { return "mysql_shared" }
func (c *mysqlSharedBaseConn) Ping(ctx context.Context) error { return c.db.PingContext(ctx) }
func (c *mysqlSharedBaseConn) Close() error                   { return c.db.Close() }

// ForTenant returns a connection with a fixed tenantID for all repos.
// Implements store.TenantScopedConnection.
func (c *mysqlSharedBaseConn) ForTenant(tenantID uuid.UUID) store.AdapterConnection {
	return &mysqlSharedTenantConn{db: c.db, tenantID: tenantID}
}

// GetSQLDB implements store.SQLDBConnection.
func (c *mysqlSharedBaseConn) GetSQLDB() store.SQLExecutor { return c.db }

// GetDriver implements store.SQLDBConnection.
func (c *mysqlSharedBaseConn) GetDriver() string { return "mysql" }

// GetMigrationExecutor implements store.MigratableConnection.
func (c *mysqlSharedBaseConn) GetMigrationExecutor() store.PgxPoolExecutor {
	return &mysqlMigrationExecutor{db: c.db}
}

// Repos on base conn panic — detecting incorrect usage without ForTenant().
func (c *mysqlSharedBaseConn) Users() repository.UserRepository {
	panic("mysql_shared: call ForTenant() first")
}
func (c *mysqlSharedBaseConn) Tokens() repository.TokenRepository {
	panic("mysql_shared: call ForTenant() first")
}
func (c *mysqlSharedBaseConn) MFA() repository.MFARepository {
	panic("mysql_shared: call ForTenant() first")
}
func (c *mysqlSharedBaseConn) Consents() repository.ConsentRepository {
	panic("mysql_shared: call ForTenant() first")
}
func (c *mysqlSharedBaseConn) RBAC() repository.RBACRepository {
	panic("mysql_shared: call ForTenant() first")
}
func (c *mysqlSharedBaseConn) Schema() repository.SchemaRepository {
	panic("mysql_shared: call ForTenant() first")
}
func (c *mysqlSharedBaseConn) EmailTokens() repository.EmailTokenRepository {
	panic("mysql_shared: call ForTenant() first")
}
func (c *mysqlSharedBaseConn) Identities() repository.IdentityRepository {
	panic("mysql_shared: call ForTenant() first")
}
func (c *mysqlSharedBaseConn) Sessions() repository.SessionRepository {
	panic("mysql_shared: call ForTenant() first")
}
func (c *mysqlSharedBaseConn) Audit() repository.AuditRepository {
	panic("mysql_shared: call ForTenant() first")
}
func (c *mysqlSharedBaseConn) Webhooks() repository.WebhookRepository {
	panic("mysql_shared: call ForTenant() first")
}
func (c *mysqlSharedBaseConn) Invitations() repository.InvitationRepository {
	panic("mysql_shared: call ForTenant() first")
}
func (c *mysqlSharedBaseConn) WebAuthn() repository.WebAuthnRepository {
	panic("mysql_shared: call ForTenant() first")
}

// Control Plane repos — not implemented in mysql_shared (FS adapter handles these).
func (c *mysqlSharedBaseConn) Tenants() repository.TenantRepository                       { return nil }
func (c *mysqlSharedBaseConn) SystemSettings() repository.SystemSettingsRepository        { return nil }
func (c *mysqlSharedBaseConn) Admins() repository.AdminRepository                         { return nil }
func (c *mysqlSharedBaseConn) AdminRefreshTokens() repository.AdminRefreshTokenRepository { return nil }
func (c *mysqlSharedBaseConn) Keys() repository.KeyRepository                             { return nil }
func (c *mysqlSharedBaseConn) APIKeys() repository.APIKeyRepository                       { return nil }
func (c *mysqlSharedBaseConn) CloudUsers() repository.CloudUserRepository                 { return nil }
func (c *mysqlSharedBaseConn) CloudInstances() repository.CloudInstanceRepository         { return nil }

// ─── mysqlSharedTenantConn ───────────────────────────────────────

// mysqlSharedTenantConn is a connection with a fixed tenantID.
// All repos use this tenantID in all queries via WHERE tenant_id = ?.
// Close() is a no-op: the pool is shared and must not be closed per-tenant.
type mysqlSharedTenantConn struct {
	db       *sql.DB
	tenantID uuid.UUID
}

func (c *mysqlSharedTenantConn) Name() string                   { return "mysql_shared" }
func (c *mysqlSharedTenantConn) Ping(ctx context.Context) error { return c.db.PingContext(ctx) }
func (c *mysqlSharedTenantConn) Close() error                   { return nil } // DO NOT close the shared pool

func (c *mysqlSharedTenantConn) Users() repository.UserRepository {
	return &sharedUserRepo{db: c.db, tenantID: c.tenantID}
}
func (c *mysqlSharedTenantConn) Tokens() repository.TokenRepository {
	return &sharedTokenRepo{db: c.db, tenantID: c.tenantID}
}
func (c *mysqlSharedTenantConn) MFA() repository.MFARepository {
	return &sharedMFARepo{db: c.db, tenantID: c.tenantID}
}
func (c *mysqlSharedTenantConn) Consents() repository.ConsentRepository {
	return &sharedConsentRepo{db: c.db, tenantID: c.tenantID}
}
func (c *mysqlSharedTenantConn) RBAC() repository.RBACRepository {
	return &sharedRBACRepo{db: c.db, tenantID: c.tenantID}
}
func (c *mysqlSharedTenantConn) Schema() repository.SchemaRepository {
	return &sharedSchemaRepo{db: c.db, tenantID: c.tenantID}
}
func (c *mysqlSharedTenantConn) EmailTokens() repository.EmailTokenRepository {
	return &sharedEmailTokenRepo{db: c.db, tenantID: c.tenantID}
}
func (c *mysqlSharedTenantConn) Identities() repository.IdentityRepository {
	return &sharedIdentityRepo{db: c.db, tenantID: c.tenantID}
}
func (c *mysqlSharedTenantConn) Sessions() repository.SessionRepository {
	return &sharedSessionRepo{db: c.db, tenantID: c.tenantID}
}
func (c *mysqlSharedTenantConn) Audit() repository.AuditRepository {
	return &sharedAuditRepo{db: c.db, tenantID: c.tenantID}
}
func (c *mysqlSharedTenantConn) Webhooks() repository.WebhookRepository {
	return &sharedWebhookRepo{db: c.db, tenantID: c.tenantID}
}
func (c *mysqlSharedTenantConn) Invitations() repository.InvitationRepository {
	return &sharedInvitationRepo{db: c.db, tenantID: c.tenantID}
}
func (c *mysqlSharedTenantConn) WebAuthn() repository.WebAuthnRepository {
	return &sharedWebAuthnRepo{db: c.db, tenantID: c.tenantID}
}

// Control Plane repos — not implemented.
func (c *mysqlSharedTenantConn) Tenants() repository.TenantRepository                       { return nil }
func (c *mysqlSharedTenantConn) SystemSettings() repository.SystemSettingsRepository        { return nil }
func (c *mysqlSharedTenantConn) Admins() repository.AdminRepository                         { return nil }
func (c *mysqlSharedTenantConn) AdminRefreshTokens() repository.AdminRefreshTokenRepository { return nil }
func (c *mysqlSharedTenantConn) Keys() repository.KeyRepository                             { return nil }
func (c *mysqlSharedTenantConn) APIKeys() repository.APIKeyRepository                       { return nil }
func (c *mysqlSharedTenantConn) CloudUsers() repository.CloudUserRepository                 { return nil }
func (c *mysqlSharedTenantConn) CloudInstances() repository.CloudInstanceRepository         { return nil }

// ─── mysqlMigrationExecutor ──────────────────────────────────────

// mysqlMigrationExecutor adapts sql.DB to the store.PgxPoolExecutor interface.
type mysqlMigrationExecutor struct {
	db *sql.DB
}

func (e *mysqlMigrationExecutor) Exec(ctx context.Context, sqlStr string, args ...any) (interface{ RowsAffected() int64 }, error) {
	result, err := e.db.ExecContext(ctx, sqlStr, args...)
	if err != nil {
		return nil, err
	}
	return &mysqlExecResult{result: result}, nil
}

func (e *mysqlMigrationExecutor) QueryRow(ctx context.Context, sqlStr string, args ...any) interface{ Scan(dest ...any) error } {
	return e.db.QueryRowContext(ctx, sqlStr, args...)
}

// mysqlExecResult wraps sql.Result to implement the RowsAffected interface.
type mysqlExecResult struct {
	result sql.Result
}

func (r *mysqlExecResult) RowsAffected() int64 {
	n, _ := r.result.RowsAffected()
	return n
}
