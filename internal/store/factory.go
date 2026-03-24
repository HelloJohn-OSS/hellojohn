package store

import (
	"context"
	"embed"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/security/secretbox"
	"github.com/google/uuid"
)

// Factory crea y configura el DataAccessLayer completo.
type Factory struct {
	cfg             FactoryConfig
	mode            OperationalMode
	caps            ModeCapabilities
	fsConn          AdapterConnection
	globalDBConn    AdapterConnection // nil si no hay Global DB configurada
	globalDataPlane AdapterConnection // nil si no hay Global Data Plane configurada
	pool            *ConnectionPool
	migrator        *Migrator
	gdpMigrator     *Migrator                    // migrator para Global Data Plane schema
	cluster         repository.ClusterRepository // opcional, para replicación

	// tenantCaches cachea clientes Redis por UUID de tenant (MED-9: evitar leak de conexiones)
	tenantCaches sync.Map // map[uuid]cache.Client
}

// FactoryConfig configuración para crear el Factory.
type FactoryConfig struct {
	// FSRoot path al directorio de datos (requerido)
	FSRoot string

	// GlobalDB configuración de DB global (opcional, para Modo 2 y 4)
	GlobalDB *DBConfig

	// DefaultTenantDB configuración default para nuevos tenants (opcional)
	DefaultTenantDB *DBConfig

	// Cluster repositorio para replicación de control plane (opcional)
	// Si es nil, operaciones mutantes son single-node.
	Cluster repository.ClusterRepository

	// MigrationsFS sistema de archivos embebido con migraciones SQL (per-tenant)
	MigrationsFS  embed.FS
	MigrationsDir string

	// GlobalMigrationsFS sistema de archivos con migraciones del schema Global DB.
	// Si el campo es el zero-value embed.FS, no se ejecutan auto-migrations para la Global DB.
	GlobalMigrationsFS  embed.FS
	GlobalMigrationsDir string

	// GlobalDataPlaneDB configuración de la DB compartida para user data con RLS (opcional).
	// Habilita los modos ModeFSGlobalDP y ModeFullGlobalDP.
	GlobalDataPlaneDB *DBConfig

	// GlobalDataPlaneMigrationsFS sistema de archivos con migraciones GDP.
	GlobalDataPlaneMigrationsFS  embed.FS
	GlobalDataPlaneMigrationsDir string

	// Mode fuerza un modo específico (0 = auto-detect)
	Mode OperationalMode

	// Logger para debug (opcional)
	Logger *log.Logger

	// SigningMasterKey para encriptar/desencriptar claves de firma (hex, 64 chars)
	SigningMasterKey string

	// OnTenantConnect callback cuando se conecta un tenant
	OnTenantConnect func(slug string, driver string)
}

// NewFactory crea un nuevo Factory.
func NewFactory(ctx context.Context, cfg FactoryConfig) (*Factory, error) {
	// Detectar modo
	mode := cfg.Mode
	if mode == 0 {
		mode = DetectMode(ModeConfig{
			FSRoot:            cfg.FSRoot,
			GlobalDB:          cfg.GlobalDB,
			DefaultTenantDB:   cfg.DefaultTenantDB,
			GlobalDataPlaneDB: cfg.GlobalDataPlaneDB,
		})
		// DetectMode returns 0 (ModeInvalid) for invalid combinations.
		// Return the exported sentinel so callers can use errors.Is().
		if mode == 0 {
			return nil, ErrInvalidModeConfig
		}
	}

	f := &Factory{
		cfg:     cfg,
		mode:    mode,
		caps:    GetCapabilities(mode),
		cluster: cfg.Cluster,
	}

	// cleanup closes all acquired resources; called on any error path.
	cleanup := func() {
		if f.pool != nil {
			f.pool.CloseAll()
		}
		if f.globalDBConn != nil {
			f.globalDBConn.Close()
		}
		if f.globalDataPlane != nil {
			f.globalDataPlane.Close()
		}
		if f.fsConn != nil {
			f.fsConn.Close()
		}
	}

	// Log modo
	if cfg.Logger != nil {
		cfg.Logger.Printf("store/v2: operating in mode %s", mode)
	}

	// Conectar al FileSystem (siempre requerido)
	fsConn, err := OpenAdapter(ctx, AdapterConfig{
		Name:             "fs",
		FSRoot:           cfg.FSRoot,
		SigningMasterKey: cfg.SigningMasterKey,
	})
	if err != nil {
		return nil, fmt.Errorf("factory: connect fs: %w", err)
	}
	f.fsConn = fsConn

	// Crear pool de conexiones para tenants
	f.pool = NewConnectionPool(f.createTenantConnection, PoolConfig{
		OnConnect: func(slug string, conn AdapterConnection) {
			if cfg.OnTenantConnect != nil {
				cfg.OnTenantConnect(slug, conn.Name())
			}
		},
	})

	// Crear migrator si hay migraciones
	if cfg.MigrationsDir != "" {
		f.migrator = NewMigrator(cfg.MigrationsFS, cfg.MigrationsDir)
	}

	// Conectar Global DB si está configurada y el modo la soporta
	if cfg.GlobalDB != nil && cfg.GlobalDB.Valid() && mode.SupportsGlobalDB() {
		globalConn, err := OpenAdapter(ctx, AdapterConfig{
			Name:         cfg.GlobalDB.Driver,
			DSN:          cfg.GlobalDB.DSN,
			MaxOpenConns: cfg.GlobalDB.MaxOpenConns,
			MaxIdleConns: cfg.GlobalDB.MaxIdleConns,
		})
		if err != nil {
			if cfg.Logger != nil {
				cfg.Logger.Printf("store: failed to connect global DB: %v", err)
			}
			cleanup()
			return nil, fmt.Errorf("factory: connect global DB: %w", err)
		}
		f.globalDBConn = globalConn
		if cfg.Logger != nil {
			cfg.Logger.Printf("store: global DB connected (%s)", cfg.GlobalDB.Driver)
		}

		// SA.1: Auto-migrate Global DB schema si se proveen migraciones
		if cfg.GlobalMigrationsDir != "" {
			if err := f.runGlobalMigrations(ctx, cfg); err != nil {
				cleanup()
				return nil, fmt.Errorf("factory: global DB auto-migration failed: %w", err)
			}
		}
	}

	// Conectar Global Data Plane si está configurado y el modo lo soporta
	if cfg.GlobalDataPlaneDB != nil && cfg.GlobalDataPlaneDB.Valid() && mode.SupportsGlobalDP() {
		// Detect adapter name from driver: "postgres" → "pg_shared", "mysql" → "mysql_shared"
		gdpAdapterName := "pg_shared"
		if cfg.GlobalDataPlaneDB.Driver == "mysql" {
			gdpAdapterName = "mysql_shared"
		}
		gdpConn, err := OpenAdapter(ctx, AdapterConfig{
			Name:         gdpAdapterName,
			DSN:          cfg.GlobalDataPlaneDB.DSN,
			MaxOpenConns: cfg.GlobalDataPlaneDB.MaxOpenConns,
			MaxIdleConns: cfg.GlobalDataPlaneDB.MaxIdleConns,
		})
		if err != nil {
			if cfg.Logger != nil {
				cfg.Logger.Printf("store: failed to connect Global Data Plane: %v", err)
			}
			cleanup()
			return nil, fmt.Errorf("factory: connect Global Data Plane: %w", err)
		}
		f.globalDataPlane = gdpConn
		if cfg.Logger != nil {
			cfg.Logger.Printf("store: Global Data Plane connected (%s)", gdpAdapterName)
		}

		// Auto-migrate GDP schema
		if cfg.GlobalDataPlaneMigrationsDir != "" {
			f.gdpMigrator = NewMigrator(cfg.GlobalDataPlaneMigrationsFS, cfg.GlobalDataPlaneMigrationsDir)
			if _, err := runMigrationsOnConn(ctx, f.gdpMigrator, gdpConn); err != nil {
				// GDP migration failure is FATAL — a GDP without schema causes silent data errors at runtime.
				cleanup()
				return nil, fmt.Errorf("factory: GDP auto-migration failed: %w", err)
			}
			if cfg.Logger != nil {
				cfg.Logger.Printf("store: GDP migrations applied successfully")
			}
		}
	}

	return f, nil
}

// runMigrationsOnConn applies migrations against a connection, detecting whether
// to use the database/sql path (MySQL) or pgxpool path (PostgreSQL).
// This replaces direct calls to RunWithPgxPool which hardcodes PG-only SQL.
func runMigrationsOnConn(ctx context.Context, migrator *Migrator, conn AdapterConnection) (*MigrationResult, error) {
	// MySQL path: use Migrator.Run() with driver-aware SQL (?, DATETIME, etc.)
	if sqlConn, ok := conn.(SQLDBConnection); ok {
		return migrator.Run(ctx, sqlConn.GetSQLDB(), sqlConn.GetDriver())
	}

	// PostgreSQL path: use RunWithPgxPool via MigratableConnection.
	if migratable, ok := conn.(MigratableConnection); ok {
		executor := migratable.GetMigrationExecutor()
		if executor == nil {
			return &MigrationResult{}, nil
		}
		return migrator.RunWithPgxPool(ctx, executor)
	}

	// Connection doesn't support migrations (e.g., FS adapter).
	return &MigrationResult{}, nil
}

// runGlobalMigrations aplica las migraciones del schema de la Global DB.
// Es idempotente: usa CREATE TABLE IF NOT EXISTS en los SQLs.
// Solo se llama cuando globalDBConn != nil y cfg.GlobalMigrationsDir != "".
func (f *Factory) runGlobalMigrations(ctx context.Context, cfg FactoryConfig) error {
	globalMigrator := NewMigrator(cfg.GlobalMigrationsFS, cfg.GlobalMigrationsDir)
	_, err := runMigrationsOnConn(ctx, globalMigrator, f.globalDBConn)
	return err
}

// Mode retorna el modo operacional detectado/configurado.
func (f *Factory) Mode() OperationalMode {
	return f.mode
}

// Cluster retorna el repositorio de cluster (nil si no configurado).
func (f *Factory) Cluster() repository.ClusterRepository {
	return f.cluster
}

// ClusterHook retorna un hook para aplicar mutaciones al cluster.
func (f *Factory) ClusterHook() *ClusterHook {
	return NewClusterHook(f.cluster, f.mode)
}

// Capabilities retorna las capacidades del modo actual.
func (f *Factory) Capabilities() ModeCapabilities {
	return f.caps
}

// ConfigAccess retorna acceso al control plane.
// Si hay Global DB disponible, usa DB como primario y FS como cache de lectura.
// Si no hay Global DB (modo FS-only), usa FS como primario.
func (f *Factory) ConfigAccess() ConfigAccess {
	if f.globalDBConn != nil && f.mode.SupportsGlobalDB() {
		return &factoryConfigAccess{
			primary: f.globalDBConn,
			cache:   f.fsConn,
		}
	}
	// Modo FS-only o Global DB no disponible: usar FS como primario
	return &factoryConfigAccess{
		primary: f.fsConn,
		cache:   nil,
	}
}

// ForTenant retorna TenantDataAccess para un tenant específico.
func (f *Factory) ForTenant(ctx context.Context, slugOrID string) (TenantDataAccess, error) {
	// Resolver tenant desde FS
	tenant, err := f.resolveTenant(ctx, slugOrID)
	if err != nil {
		return nil, err
	}

	// Obtener o crear conexión de datos
	dataConn, err := f.getDataConnection(ctx, tenant)
	if err != nil {
		return nil, err
	}

	// Obtener o crear cache
	cacheClient := f.getCache(ctx, tenant)

	return &tenantAccess{
		tenant:   tenant,
		dataConn: dataConn,
		fsConn:   f.fsConn,
		cache:    cacheClient,
		mode:     f.mode,
	}, nil
}

// InvalidateTenantCache es un no-op en Factory porque no utiliza caché en RAM.
func (f *Factory) InvalidateTenantCache(tenantID string) {
	// No-op
}

// Close cierra todas las conexiones.
func (f *Factory) Close() error {
	var errs []error

	// Close cached Redis clients (MED-9)
	f.tenantCaches.Range(func(_, v any) bool {
		if closer, ok := v.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		return true
	})

	if f.pool != nil {
		if err := f.pool.CloseAll(); err != nil {
			errs = append(errs, err)
		}
	}

	if f.globalDataPlane != nil {
		if err := f.globalDataPlane.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if f.globalDBConn != nil {
		if err := f.globalDBConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if f.fsConn != nil {
		if err := f.fsConn.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("factory close errors: %v", errs)
	}
	return nil
}

// Stats retorna estadísticas del factory.
func (f *Factory) Stats() FactoryStats {
	poolStats := f.pool.Stats()
	return FactoryStats{
		Mode:        f.mode.String(),
		ActiveConns: poolStats.TotalActive,
		Connections: poolStats.Connections,
	}
}

// FactoryStats estadísticas del factory.
type FactoryStats struct {
	Mode        string
	ActiveConns int
	Connections map[string]ConnectionStats
}

// MigrateTenant ejecuta migraciones para un tenant específico.
// Retorna ErrNoDBForTenant si el tenant no tiene DB configurada.
func (f *Factory) MigrateTenant(ctx context.Context, slugOrID string) (*MigrationResult, error) {
	if f.migrator == nil {
		return &MigrationResult{}, nil // No hay migrator configurado
	}

	// Resolver tenant
	tenant, err := f.resolveTenant(ctx, slugOrID)
	if err != nil {
		return nil, err
	}

	// Obtener conexión de datos
	dataConn, err := f.getDataConnection(ctx, tenant)
	if err != nil {
		return nil, err
	}
	if dataConn == nil {
		return nil, ErrNoDBForTenant
	}

	// Ejecutar migraciones (detecta MySQL vs PG automáticamente)
	return runMigrationsOnConn(ctx, f.migrator, dataConn)
}

// ─── Helpers internos ───

func (f *Factory) resolveTenant(ctx context.Context, slugOrID string) (*repository.Tenant, error) {
	// 1. Intentar FS — UUID first (primary path post-migration), slug as fallback
	tenants := f.fsConn.Tenants()
	if tenants != nil {
		if t, err := tenants.GetByID(ctx, slugOrID); err == nil {
			return t, nil
		}
		if t, err := tenants.GetBySlug(ctx, slugOrID); err == nil {
			return t, nil
		}
	}

	// 2. Si hay Global DB, intentar desde DB
	// Necesario en ModeFullDB donde el FS puede no tener todos los tenants.
	if f.globalDBConn != nil {
		dbTenants := f.globalDBConn.Tenants()
		if dbTenants != nil {
			if t, err := dbTenants.GetByID(ctx, slugOrID); err == nil {
				return t, nil
			}
			if t, err := dbTenants.GetBySlug(ctx, slugOrID); err == nil {
				return t, nil
			}
		}
	}

	return nil, ErrTenantNotFound
}

func (f *Factory) getDataConnection(ctx context.Context, tenant *repository.Tenant) (AdapterConnection, error) {
	// Nota: No hacemos early-return para ModeFSOnly porque un tenant individual
	// puede tener su propia DB configurada aunque no haya GlobalDB ni DefaultTenantDB.

	// Determinar configuración de DB
	var dbCfg *DBConfig

	// Prioridad: tenant-specific > default
	if tenant.Settings.UserDB != nil && tenant.Settings.UserDB.Driver != "" {
		dbCfg = &DBConfig{
			Driver: tenant.Settings.UserDB.Driver,
			DSN:    tenant.Settings.UserDB.DSN,
			Schema: tenant.Settings.UserDB.Schema,
		}
		// Si tiene DSNEnc, descifrar con secretbox.
		// Error de desencriptación sí es fatal: indica configuración corrompida.
		if dbCfg.DSN == "" && tenant.Settings.UserDB.DSNEnc != "" {
			decrypted, err := decryptDSN(tenant.Settings.UserDB.DSNEnc)
			if err != nil {
				if f.cfg.Logger != nil {
					f.cfg.Logger.Printf("store/v2: failed to decrypt DSN for tenant %s: %v", tenant.Slug, err)
				}
				return nil, fmt.Errorf("failed to decrypt DSN for tenant %s: %w", tenant.Slug, err)
			}
			dbCfg.DSN = decrypted
		}
	} else if f.cfg.DefaultTenantDB != nil {
		dbCfg = f.cfg.DefaultTenantDB
	}

	// Sin configuración de DB aislada → intentar Global Data Plane
	if dbCfg == nil || !dbCfg.Valid() {
		if f.globalDataPlane != nil {
			scoped, ok := f.globalDataPlane.(TenantScopedConnection)
			if !ok {
				return nil, fmt.Errorf("factory: globalDataPlane does not implement TenantScopedConnection")
			}
			tenantUUID, err := uuid.Parse(tenant.ID)
			if err != nil {
				if f.cfg.Logger != nil {
					f.cfg.Logger.Printf("store: tenant %s has invalid UUID %q for GDP: %v", tenant.Slug, tenant.ID, err)
				}
				return nil, fmt.Errorf("factory: invalid tenant UUID for GDP: %w", err)
			}
			return scoped.ForTenant(tenantUUID), nil
		}
		// No DB configurada y no hay GDP: tenant opera en modo Control Plane (FS) solamente.
		return nil, nil
	}

	// Intentar conectar al pool. Si la DB está caída o inaccesible, NO es un error
	// fatal para ForTenant(): el tenant sigue siendo válido para operaciones de
	// Control Plane (clients, scopes, keys). El error se diferirá hasta que código
	// intente usar métodos Data Plane (Users, Tokens, etc.) vía RequireDB().
	conn, err := f.pool.Get(ctx, tenant.Slug, AdapterConfig{
		Name:         dbCfg.Driver,
		DSN:          dbCfg.DSN,
		Schema:       dbCfg.Schema,
		MaxOpenConns: dbCfg.MaxOpenConns,
		MaxIdleConns: dbCfg.MaxIdleConns,
	})
	if err != nil {
		if f.cfg.Logger != nil {
			f.cfg.Logger.Printf(`{"level":"warn","tenant":"%s","driver":"%s","err":"%v","msg":"tenant DB unavailable, Control Plane operations only"}`,
				tenant.Slug, dbCfg.Driver, err)
		}
		// Retornar (nil, nil): TenantDataAccess es válido para Control Plane.
		// HasDB() → false, RequireDB() → ErrNoDBForTenant.
		return nil, nil
	}

	return conn, nil
}

func (f *Factory) createTenantConnection(ctx context.Context, slug string, cfg AdapterConfig) (AdapterConnection, error) {
	conn, err := OpenAdapter(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("factory: connect %s for %s: %w", cfg.Name, slug, err)
	}

	// Ejecutar migraciones si están configuradas (detecta MySQL vs PG automáticamente)
	if f.migrator != nil {
		if _, err := runMigrationsOnConn(ctx, f.migrator, conn); err != nil {
			conn.Close()
			return nil, fmt.Errorf("factory: auto-migrate %s: %w", slug, err)
		}
	}

	return conn, nil
}

func (f *Factory) getCache(ctx context.Context, tenant *repository.Tenant) cache.Client {
	// Si no hay configuración de cache, usar memory default
	if tenant.Settings.Cache == nil || !tenant.Settings.Cache.Enabled {
		return cache.NewMemory(tenant.Slug + ":")
	}

	// Cachear por UUID para evitar abrir un nuevo pool Redis por request (MED-9)
	if cached, ok := f.tenantCaches.Load(tenant.ID); ok {
		return cached.(cache.Client)
	}

	cfg := cache.Config{
		Driver:   tenant.Settings.Cache.Driver,
		Host:     tenant.Settings.Cache.Host,
		Port:     tenant.Settings.Cache.Port,
		Password: tenant.Settings.Cache.Password,
		DB:       tenant.Settings.Cache.DB,
		Prefix:   tenant.Settings.Cache.Prefix,
	}

	c, err := cache.New(cfg)
	if err != nil {
		// Fallback a memory
		return cache.NewMemory(tenant.Slug + ":")
	}

	// Store only on success; use LoadOrStore to avoid race
	if actual, loaded := f.tenantCaches.LoadOrStore(tenant.ID, c); loaded {
		// Another goroutine stored first — close the one we just opened
		if closer, ok := c.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
		return actual.(cache.Client)
	}
	return c
}

// ─── ConfigAccess Implementation ───

// factoryConfigAccess implementa ConfigAccess.
// En modo DB-primary: primary=GlobalDB, cache=FS.
// En modo FS-only: primary=FS, cache=nil.
type factoryConfigAccess struct {
	primary AdapterConnection // Global DB (o FS en modo solo-FS)
	cache   AdapterConnection // FS como caché de lectura (nil en modo solo-FS)
}

func (c *factoryConfigAccess) Tenants() repository.TenantRepository {
	if c.cache != nil {
		// Modo DB-primary: decorar con cache Read-Through
		return NewCachedTenantRepo(c.primary.Tenants(), c.cache.Tenants())
	}
	return c.primary.Tenants()
}

func (c *factoryConfigAccess) SystemSettings() repository.SystemSettingsRepository {
	// En modo DB-primary, usar DB como fuente de verdad.
	if c.primary != nil {
		if repo := c.primary.SystemSettings(); repo != nil {
			return repo
		}
	}
	// Fallback a FS en modo solo-FS o cuando DB no implementa el repo.
	if c.cache != nil {
		return c.cache.SystemSettings()
	}
	return nil
}

func (c *factoryConfigAccess) Clients(tenantID string) repository.ClientRepository {
	if c.cache != nil {
		// Modo DB-primary: pasar UUID directamente al repo builder
		if builder, ok := c.primary.(interface {
			NewClientRepo(tenantID string) repository.ClientRepository
		}); ok {
			return builder.NewClientRepo(tenantID)
		}
	}
	// Modo FS-only: resolver UUID→slug para rutas del filesystem
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	slug := tenantID // fallback defensivo
	if t, err := c.primary.Tenants().GetByID(ctx, tenantID); err == nil {
		slug = t.Slug
	}
	raw := mustFSRaw(c.primary)
	return &tenantScopedClientRepo{delegate: raw.RawClients(), tenantSlug: slug}
}

func (c *factoryConfigAccess) Scopes(tenantID string) repository.ScopeRepository {
	if c.cache != nil {
		if builder, ok := c.primary.(interface {
			NewScopeRepo(tenantID string) repository.ScopeRepository
		}); ok {
			return builder.NewScopeRepo(tenantID)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	slug := tenantID
	if t, err := c.primary.Tenants().GetByID(ctx, tenantID); err == nil {
		slug = t.Slug
	}
	raw := mustFSRaw(c.primary)
	return &tenantScopedScopeRepo{delegate: raw.RawScopes(), tenantSlug: slug}
}

func (c *factoryConfigAccess) Claims(tenantID string) repository.ClaimRepository {
	if c.cache != nil {
		if builder, ok := c.primary.(interface {
			NewClaimsRepo(tenantID string) repository.ClaimRepository
		}); ok {
			return builder.NewClaimsRepo(tenantID)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	slug := tenantID
	if t, err := c.primary.Tenants().GetByID(ctx, tenantID); err == nil {
		slug = t.Slug
	}
	raw := mustFSRaw(c.primary)
	return &tenantScopedClaimRepo{delegate: raw.RawClaims(), tenantSlug: slug}
}

func (c *factoryConfigAccess) Keys() repository.KeyRepository {
	// Keys SIEMPRE desde FS (las claves JWT viven en disco, nunca en DB)
	if c.cache != nil {
		return c.cache.Keys() // cache es el fsConn en modo DB-primary
	}
	return c.primary.Keys()
}

func (c *factoryConfigAccess) Admins() repository.AdminRepository {
	return c.primary.Admins()
}

func (c *factoryConfigAccess) AdminRefreshTokens() repository.AdminRefreshTokenRepository {
	return c.primary.AdminRefreshTokens()
}

func (c *factoryConfigAccess) APIKeys() repository.APIKeyRepository {
	// API Keys SIEMPRE desde FS (como Keys)
	if c.cache != nil {
		return c.cache.APIKeys() // cache es el fsConn en modo DB-primary
	}
	return c.primary.APIKeys()
}

func (c *factoryConfigAccess) CloudUsers() repository.CloudUserRepository {
	// primary = globalDB pgConn (DB mode) or fsConn (FS-only mode)
	return c.primary.CloudUsers()
}

func (c *factoryConfigAccess) CloudInstances() repository.CloudInstanceRepository {
	// primary = globalDB pgConn (DB mode) or fsConn (FS-only mode)
	return c.primary.CloudInstances()
}

// ─── TenantDataAccess Implementation ───

type tenantAccess struct {
	tenant   *repository.Tenant
	dataConn AdapterConnection // nil si modo FS-only
	fsConn   AdapterConnection
	cache    cache.Client
	mode     OperationalMode
}

func (t *tenantAccess) Slug() string { return t.tenant.Slug }
func (t *tenantAccess) ID() string   { return t.tenant.ID }

func (t *tenantAccess) Settings() *repository.TenantSettings {
	return &t.tenant.Settings
}

func (t *tenantAccess) Driver() string {
	if t.dataConn == nil {
		return "none"
	}
	return t.dataConn.Name()
}

// Data plane repos (desde dataConn).
// Si dataConn es nil (DB no disponible), retorna stubs que devuelven ErrNoDBForTenant.
// Esto evita nil pointer panics si un caller olvida RequireDB().
func (t *tenantAccess) Users() repository.UserRepository {
	if t.dataConn == nil {
		return noDBUsers
	}
	return t.dataConn.Users()
}

func (t *tenantAccess) Tokens() repository.TokenRepository {
	if t.dataConn == nil {
		return noDBTokens
	}
	return t.dataConn.Tokens()
}

func (t *tenantAccess) MFA() repository.MFARepository {
	if t.dataConn == nil {
		return noDBMFA
	}
	return t.dataConn.MFA()
}

func (t *tenantAccess) Consents() repository.ConsentRepository {
	if t.dataConn == nil {
		return noDBConsents
	}
	return t.dataConn.Consents()
}

func (t *tenantAccess) RBAC() repository.RBACRepository {
	if t.dataConn == nil {
		return noDBRBAC
	}
	return t.dataConn.RBAC()
}

func (t *tenantAccess) Schema() repository.SchemaRepository {
	if t.dataConn == nil {
		return noDBSchema
	}
	return t.dataConn.Schema()
}

func (t *tenantAccess) EmailTokens() repository.EmailTokenRepository {
	if t.dataConn == nil {
		return noDBEmailTkns
	}
	return t.dataConn.EmailTokens()
}

func (t *tenantAccess) Identities() repository.IdentityRepository {
	if t.dataConn == nil {
		return noDBIdentities
	}
	return t.dataConn.Identities()
}

func (t *tenantAccess) Sessions() repository.SessionRepository {
	if t.dataConn == nil {
		return noDBSessions
	}
	return t.dataConn.Sessions()
}

func (t *tenantAccess) Audit() repository.AuditRepository {
	if t.dataConn == nil {
		return noDBaudit
	}
	return t.dataConn.Audit()
}

func (t *tenantAccess) Webhooks() repository.WebhookRepository {
	if t.dataConn == nil {
		return noDBwebhooks
	}
	return t.dataConn.Webhooks()
}

func (t *tenantAccess) Invitations() repository.InvitationRepository {
	if t.dataConn == nil {
		return noDBInvitations
	}
	return t.dataConn.Invitations()
}

func (t *tenantAccess) WebAuthn() repository.WebAuthnRepository {
	if t.dataConn == nil {
		return noDBWebAuthn
	}
	return t.dataConn.WebAuthn()
}

// Config repos (desde fsConn - control plane)
func (t *tenantAccess) Clients() repository.ClientRepository {
	raw := mustFSRaw(t.fsConn)
	return &tenantScopedClientRepo{
		delegate:   raw.RawClients(),
		tenantSlug: t.tenant.Slug,
	}
}

func (t *tenantAccess) Scopes() repository.ScopeRepository {
	raw := mustFSRaw(t.fsConn)
	return &tenantScopedScopeRepo{
		delegate:   raw.RawScopes(),
		tenantSlug: t.tenant.Slug,
	}
}

func (t *tenantAccess) Claims() repository.ClaimRepository {
	raw := mustFSRaw(t.fsConn)
	return &tenantScopedClaimRepo{
		delegate:   raw.RawClaims(),
		tenantSlug: t.tenant.Slug,
	}
}

func (t *tenantAccess) Cache() cache.Client {
	return t.cache
}

// noopMailSender is a safe no-op implementation of MailSender used when no email
// service is configured for the tenant. It prevents nil pointer panics without
// silently dropping emails — callers that care about delivery should check tenant
// settings before calling Mailer().
type noopMailSender struct{}

func (noopMailSender) Send(_ context.Context, _, _, _ string) error { return nil }

func (t *tenantAccess) Mailer() MailSender {
	return noopMailSender{}
}

func (t *tenantAccess) HasDB() bool {
	return t.dataConn != nil
}

func (t *tenantAccess) RequireDB() error {
	if t.dataConn == nil {
		return ErrNoDBForTenant
	}
	return nil
}

func (t *tenantAccess) CacheRepo() repository.CacheRepository {
	return NewCacheRepoWrapper(t.cache)
}

func (t *tenantAccess) InfraStats(ctx context.Context) (*TenantInfraStats, error) {
	stats := &TenantInfraStats{
		TenantSlug:   t.tenant.Slug,
		TenantID:     t.tenant.ID,
		Mode:         t.mode.String(),
		HasDB:        t.dataConn != nil,
		CacheEnabled: t.cache != nil,
		CollectedAt:  time.Now(),
	}

	// Stats de DB si hay conexión
	if t.dataConn != nil {
		healthy := true
		if err := t.dataConn.Ping(ctx); err != nil {
			healthy = false
		}
		stats.DBStats = &DBConnectionStats{
			Driver:  t.dataConn.Name(),
			Healthy: healthy,
		}
	}

	// Stats de cache si está habilitado
	if t.cache != nil {
		cacheStats, err := t.cache.Stats(ctx)
		if err == nil {
			stats.CacheStats = &CacheInfo{
				Driver:     cacheStats.Driver,
				Keys:       cacheStats.Keys,
				UsedMemory: cacheStats.UsedMemory,
				Hits:       cacheStats.Hits,
				Misses:     cacheStats.Misses,
			}
		}
	}

	return stats, nil
}

// decryptDSN descifra un DSN encriptado usando secretbox.
// Retorna error si el formato no es válido o la clave no está configurada.
func decryptDSN(encryptedDSN string) (string, error) {
	if encryptedDSN == "" {
		return "", fmt.Errorf("empty encrypted DSN")
	}
	return secretbox.Decrypt(encryptedDSN)
}
