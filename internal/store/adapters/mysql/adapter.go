// Package mysql implementa el adapter MySQL para el store DAL.
// Usa database/sql con github.com/go-sql-driver/mysql.
//
// Este adapter implementa la interfaz store.AdapterConnection y provee
// acceso a los repositorios del Data Plane (Users, Tokens, Sessions, etc.).
// El Control Plane (Tenants, Clients, Keys) sigue siendo manejado por el
// adapter de FileSystem.
//
// Requisitos:
//   - MySQL 8.0+ (para soporte de UUID() y funciones JSON)
//   - DSN format: user:password@tcp(host:port)/database?parseTime=true
package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

func init() {
	store.RegisterAdapter(&mysqlAdapter{})
}

// mysqlAdapter implementa store.Adapter para MySQL.
type mysqlAdapter struct{}

func (a *mysqlAdapter) Name() string { return "mysql" }

func (a *mysqlAdapter) Connect(ctx context.Context, cfg store.AdapterConfig) (store.AdapterConnection, error) {
	// Abrir conexión a MySQL
	// El DSN debe incluir parseTime=true para que los timestamps se conviertan a time.Time
	// Ejemplo: user:password@tcp(localhost:3306)/dbname?parseTime=true&multiStatements=true
	db, err := sql.Open("mysql", cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("mysql: open: %w", err)
	}

	// Configurar pool de conexiones
	if cfg.MaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
	} else {
		db.SetMaxOpenConns(10)
	}
	if cfg.MaxIdleConns > 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConns)
	} else {
		db.SetMaxIdleConns(2)
	}
	// Tiempo máximo que una conexión puede estar abierta
	db.SetConnMaxLifetime(30 * time.Minute)
	// Tiempo máximo que una conexión puede estar idle antes de cerrarse
	db.SetConnMaxIdleTime(5 * time.Minute)

	// Verificar conectividad
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("mysql: ping failed: %w", err)
	}

	return &mysqlConnection{db: db, schema: cfg.Schema}, nil
}

// mysqlConnection representa una conexión activa a MySQL.
// Implementa store.AdapterConnection.
type mysqlConnection struct {
	db     *sql.DB
	schema string // Schema/database name (opcional, para multi-tenant)
}

func (c *mysqlConnection) Name() string { return "mysql" }

func (c *mysqlConnection) Ping(ctx context.Context) error {
	return c.db.PingContext(ctx)
}

func (c *mysqlConnection) Close() error {
	return c.db.Close()
}

// ─────────────────────────────────────────────────────────────────────────────
// Data Plane Repositories
// Estos repositorios manejan datos de runtime específicos de cada tenant.
// ─────────────────────────────────────────────────────────────────────────────

func (c *mysqlConnection) Users() repository.UserRepository {
	return &userRepo{db: c.db}
}

func (c *mysqlConnection) Tokens() repository.TokenRepository {
	return &tokenRepo{db: c.db}
}

func (c *mysqlConnection) MFA() repository.MFARepository {
	return &mfaRepo{db: c.db}
}

func (c *mysqlConnection) Consents() repository.ConsentRepository {
	return &consentRepo{db: c.db}
}

// Scopes es un repo de Data Plane: los scopes custom del tenant en DB.
func (c *mysqlConnection) Scopes() repository.ScopeRepository {
	return &scopeRepo{db: c.db}
}

func (c *mysqlConnection) RBAC() repository.RBACRepository {
	return &rbacRepo{db: c.db}
}

func (c *mysqlConnection) Schema() repository.SchemaRepository {
	return &schemaRepo{db: c.db}
}

func (c *mysqlConnection) EmailTokens() repository.EmailTokenRepository {
	return &emailTokenRepo{db: c.db}
}

func (c *mysqlConnection) Identities() repository.IdentityRepository {
	return &identityRepo{db: c.db}
}

func (c *mysqlConnection) Sessions() repository.SessionRepository {
	return &sessionRepo{db: c.db}
}

func (c *mysqlConnection) Audit() repository.AuditRepository {
	return &auditRepo{db: c.db}
}

func (c *mysqlConnection) Webhooks() repository.WebhookRepository {
	return &webhookRepo{db: c.db}
}

func (c *mysqlConnection) Invitations() repository.InvitationRepository {
	return &invitationMysqlRepo{db: c.db}
}

func (c *mysqlConnection) WebAuthn() repository.WebAuthnRepository {
	return &webAuthnMysqlRepo{db: c.db}
}

// Control Plane Repositories — repos sobre la Global DB (cp_* tables)
func (c *mysqlConnection) Tenants() repository.TenantRepository {
	return &cpTenantRepoMySQL{db: c.db}
}
func (c *mysqlConnection) SystemSettings() repository.SystemSettingsRepository {
	return &mysqlSystemSettingsRepo{db: c.db}
}

func (c *mysqlConnection) Admins() repository.AdminRepository {
	return &cpAdminRepoMySQL{db: c.db}
}

func (c *mysqlConnection) AdminRefreshTokens() repository.AdminRefreshTokenRepository {
	return &cpAdminRefreshTokenRepoMySQL{db: c.db}
}

func (c *mysqlConnection) Keys() repository.KeyRepository {
	return nil // Keys viven en FS
}

func (c *mysqlConnection) APIKeys() repository.APIKeyRepository {
	return nil // API Keys viven en FS
}

func (c *mysqlConnection) CloudUsers() repository.CloudUserRepository         { return nil }
func (c *mysqlConnection) CloudInstances() repository.CloudInstanceRepository { return nil }

// NewClientRepo construye un repo CP de clientes para el tenantID dado.
func (c *mysqlConnection) NewClientRepo(tenantID string) repository.ClientRepository {
	return &cpClientRepoMySQL{db: c.db, tenantID: tenantID}
}

// NewScopeRepo construye un repo CP de scopes para el tenantID dado.
func (c *mysqlConnection) NewScopeRepo(tenantID string) repository.ScopeRepository {
	return &cpScopeRepoMySQL{db: c.db, tenantID: tenantID}
}

// NewClaimsRepo construye un repo CP de claims para el tenantID dado.
func (c *mysqlConnection) NewClaimsRepo(tenantID string) repository.ClaimRepository {
	return &cpClaimsRepoMySQL{db: c.db, tenantID: tenantID}
}

// ─────────────────────────────────────────────────────────────────────────────
// Migraciones
// ─────────────────────────────────────────────────────────────────────────────

// GetMigrationExecutor implementa store.MigratableConnection.
// Retorna un wrapper que permite ejecutar migraciones usando database/sql.
func (c *mysqlConnection) GetMigrationExecutor() store.PgxPoolExecutor {
	return &mysqlMigrationExecutor{db: c.db}
}

// mysqlMigrationExecutor adapta sql.DB a la interfaz store.PgxPoolExecutor.
// Esto permite usar el mismo sistema de migraciones que PostgreSQL.
type mysqlMigrationExecutor struct {
	db *sql.DB
}

func (e *mysqlMigrationExecutor) Exec(ctx context.Context, sqlStr string, args ...any) (interface{ RowsAffected() int64 }, error) {
	// Convertir placeholders de PostgreSQL ($1, $2) a MySQL (?, ?)
	// Nota: Las migraciones MySQL deben usar ? directamente
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

// ─────────────────────────────────────────────────────────────────────────────
// Repository struct placeholders
// Estos structs serán implementados en archivos separados.
// Por ahora, definimos los tipos base para que compile.
// ─────────────────────────────────────────────────────────────────────────────

type userRepo struct{ db *sql.DB }
type tokenRepo struct{ db *sql.DB }
type sessionRepo struct{ db *sql.DB }
type mfaRepo struct{ db *sql.DB }
type consentRepo struct{ db *sql.DB }
type scopeRepo struct{ db *sql.DB }
type rbacRepo struct{ db *sql.DB }
type schemaRepo struct{ db *sql.DB }
type emailTokenRepo struct{ db *sql.DB }
type identityRepo struct{ db *sql.DB }
type webhookRepo struct{ db *sql.DB }
