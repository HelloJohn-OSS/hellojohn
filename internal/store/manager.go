package store

import (
	"context"
	"embed"
	"fmt"
	"log"
	"sync"

	"golang.org/x/sync/singleflight"

	"github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// DataAccessLayer es el punto de entrada principal para acceso a datos.
// Implementado por Factory.
type DataAccessLayer interface {
	// ForTenant retorna acceso a datos para un tenant específico.
	// Acepta slug ("acme") o UUID ("550e8400-...") indistintamente —
	// la resolución slug↔UUID ocurre aquí, en el único punto de entrada.
	ForTenant(ctx context.Context, slugOrID string) (TenantDataAccess, error)

	// ConfigAccess retorna acceso al control plane (siempre disponible).
	ConfigAccess() ConfigAccess

	// InvalidateTenantCache limpia el TenantDataAccess cacheado para el tenant
	// identificado por slug. Borra tanto la entrada slug como la entrada UUID
	// del cache interno (sync.Map) para evitar entradas huérfanas.
	// Uso típico: llamar tras UpdateTenantSettings para forzar recarga de config.
	InvalidateTenantCache(slug string)

	// Mode retorna el modo operacional actual.
	Mode() OperationalMode

	// Capabilities retorna las capacidades del modo actual.
	Capabilities() ModeCapabilities

	// Stats retorna estadísticas de conexiones.
	Stats() FactoryStats

	// Cluster retorna el repositorio de cluster (nil si no configurado).
	Cluster() repository.ClusterRepository

	// MigrateTenant ejecuta migraciones para un tenant específico.
	MigrateTenant(ctx context.Context, slugOrID string) (*MigrationResult, error)

	// Close cierra todas las conexiones.
	Close() error
}

// TenantDataAccess agrupa todos los repositorios para un tenant específico.
type TenantDataAccess interface {
	// Identificación
	Slug() string
	ID() string
	Settings() *repository.TenantSettings
	Driver() string

	// Data plane (requieren DB)
	Users() repository.UserRepository
	Tokens() repository.TokenRepository
	MFA() repository.MFARepository
	Consents() repository.ConsentRepository
	RBAC() repository.RBACRepository
	Schema() repository.SchemaRepository
	EmailTokens() repository.EmailTokenRepository
	Identities() repository.IdentityRepository
	Sessions() repository.SessionRepository
	Audit() repository.AuditRepository
	Webhooks() repository.WebhookRepository
	Invitations() repository.InvitationRepository
	WebAuthn() repository.WebAuthnRepository

	// Control plane (siempre disponibles vía FS)
	Clients() repository.ClientRepository
	Scopes() repository.ScopeRepository
	Claims() repository.ClaimRepository

	// Infraestructura
	Cache() cache.Client
	CacheRepo() repository.CacheRepository
	Mailer() MailSender

	// Operations
	InfraStats(ctx context.Context) (*TenantInfraStats, error)

	// Helpers
	HasDB() bool
	RequireDB() error
}

// ConfigAccess provee acceso al control plane (configuración global).
type ConfigAccess interface {
	Tenants() repository.TenantRepository
	Clients(tenantSlug string) repository.ClientRepository
	Scopes(tenantSlug string) repository.ScopeRepository
	Claims(tenantSlug string) repository.ClaimRepository
	Keys() repository.KeyRepository
	Admins() repository.AdminRepository
	AdminRefreshTokens() repository.AdminRefreshTokenRepository
	APIKeys() repository.APIKeyRepository

	// ─── Cloud Control Plane ───
	CloudUsers() repository.CloudUserRepository
	CloudInstances() repository.CloudInstanceRepository
}

// MailSender interface para envío de emails.
type MailSender interface {
	Send(ctx context.Context, to, subject, body string) error
}

// ─── Manager (wrapper simplificado sobre Factory) ───

// Manager es un wrapper thread-safe sobre Factory que cachea TenantDataAccess.
// Útil cuando se quiere reutilizar TenantDataAccess entre requests.
type Manager struct {
	factory *Factory

	// Cache de TenantDataAccess
	tenants sync.Map // map[slug|uuid]TenantDataAccess

	// group previene el thundering-herd: múltiples goroutines concurrentes
	// que lleguen simultáneamente con el mismo slugOrID solo disparan una
	// llamada real a factory.ForTenant.
	group singleflight.Group
}

// ManagerConfig configuración para crear un Manager.
type ManagerConfig struct {
	FSRoot          string
	GlobalDB        *DBConfig
	DefaultTenantDB *DBConfig
	MigrationsFS    embed.FS
	MigrationsDir   string
	// GlobalMigrationsFS/Dir: migraciones para el schema de la Global DB.
	// Si se proveen y hay GlobalDB configurada, se aplican automáticamente al arrancar.
	GlobalMigrationsFS  embed.FS
	GlobalMigrationsDir string
	// GlobalDataPlaneDB: shared DB con RLS para tenants sin DB aislada.
	GlobalDataPlaneDB *DBConfig
	// GlobalDataPlaneMigrationsFS/Dir: migraciones del schema GDP.
	GlobalDataPlaneMigrationsFS  embed.FS
	GlobalDataPlaneMigrationsDir string
	Logger                       *log.Logger
	SigningMasterKey             string // hex, 64 chars - for encrypting signing keys
}

// NewManager crea un nuevo Manager.
func NewManager(ctx context.Context, cfg ManagerConfig) (*Manager, error) {
	factory, err := NewFactory(ctx, FactoryConfig{
		FSRoot:                       cfg.FSRoot,
		GlobalDB:                     cfg.GlobalDB,
		DefaultTenantDB:              cfg.DefaultTenantDB,
		MigrationsFS:                 cfg.MigrationsFS,
		MigrationsDir:                cfg.MigrationsDir,
		GlobalMigrationsFS:           cfg.GlobalMigrationsFS,
		GlobalMigrationsDir:          cfg.GlobalMigrationsDir,
		GlobalDataPlaneDB:            cfg.GlobalDataPlaneDB,
		GlobalDataPlaneMigrationsFS:  cfg.GlobalDataPlaneMigrationsFS,
		GlobalDataPlaneMigrationsDir: cfg.GlobalDataPlaneMigrationsDir,
		Logger:                       cfg.Logger,
		SigningMasterKey:             cfg.SigningMasterKey,
	})
	if err != nil {
		return nil, err
	}

	return &Manager{factory: factory}, nil
}

// ForTenant retorna TenantDataAccess, cacheando el resultado.
// Si el tenant tiene DB configurada pero la conexión falló (lazy connection),
// el TDA NO se cachea para permitir reintentos en requests posteriores.
// singleflight.Group garantiza que múltiples goroutines concurrentes con el
// mismo slugOrID solo disparen UNA llamada a factory.ForTenant (thundering-herd).
func (m *Manager) ForTenant(ctx context.Context, slugOrID string) (TenantDataAccess, error) {
	// Fast path: ya está en cache
	if val, ok := m.tenants.Load(slugOrID); ok {
		return val.(TenantDataAccess), nil
	}

	// Slow path: crear único (singleflight colapsa llamadas concurrentes).
	// Usamos context.Background() como clave porque singleflight no soporta
	// cancelación individual; el contexto se pasa al factory internamente.
	v, err, _ := m.group.Do(slugOrID, func() (any, error) {
		// Double-check dentro del grupo para evitar trabajo redundante
		if val, ok := m.tenants.Load(slugOrID); ok {
			return val.(TenantDataAccess), nil
		}

		tda, err := m.factory.ForTenant(ctx, slugOrID)
		if err != nil {
			return nil, err
		}

		// Solo cachear si la conexión DB está completa o si el tenant no tiene DB configurada.
		// Si el tenant tiene DB configurada pero la conexión falló (HasDB() == false),
		// NO cachear para que el próximo request reintente la conexión.
		dbConfigured := tda.Settings() != nil &&
			tda.Settings().UserDB != nil &&
			tda.Settings().UserDB.Driver != ""
		if tda.HasDB() || !dbConfigured {
			m.tenants.Store(tda.Slug(), tda)
			if tda.ID() != tda.Slug() {
				m.tenants.Store(tda.ID(), tda)
			}
		}

		return tda, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(TenantDataAccess), nil
}

// ConfigAccess retorna acceso al control plane.
func (m *Manager) ConfigAccess() ConfigAccess {
	return m.factory.ConfigAccess()
}

// Mode retorna el modo operacional.
func (m *Manager) Mode() OperationalMode {
	return m.factory.Mode()
}

// Cluster retorna el repositorio de cluster (nil si no configurado).
func (m *Manager) Cluster() repository.ClusterRepository {
	return m.factory.Cluster()
}

// Capabilities retorna las capacidades del modo.
func (m *Manager) Capabilities() ModeCapabilities {
	return m.factory.Capabilities()
}

// Stats retorna estadísticas.
func (m *Manager) Stats() FactoryStats {
	return m.factory.Stats()
}

// ClearCache limpia el cache de TenantDataAccess.
func (m *Manager) ClearCache() {
	m.tenants.Range(func(k, _ any) bool {
		m.tenants.Delete(k)
		return true
	})
}

// clearTenantBySlug es el helper interno que borra ambas entradas del sync.Map
// dado el slug. Primero busca el TDA por slug para obtener el UUID, luego
// borra ambas entradas.
func (m *Manager) clearTenantBySlug(slug string) {
	// Obtener el TDA desde cache para conocer su UUID
	if v, ok := m.tenants.Load(slug); ok {
		tda := v.(TenantDataAccess)
		tenantUUID := tda.ID()
		m.tenants.Delete(slug)
		if tenantUUID != slug {
			m.tenants.Delete(tenantUUID)
		}
	} else {
		// El slug no está en cache; borrar de todas formas (caso defensivo)
		m.tenants.Delete(slug)
	}
}

// ClearTenant limpia el cache para un tenant específico (slug y UUID).
func (m *Manager) ClearTenant(slug string) {
	m.clearTenantBySlug(slug)
}

// InvalidateTenantCache implementa DataAccessLayer exponiendo el borrado de caché.
// Borra tanto la entrada slug como la entrada UUID del sync.Map.
func (m *Manager) InvalidateTenantCache(slug string) {
	m.clearTenantBySlug(slug)
}

// RefreshTenant cierra la conexión existente y la recrea con la configuración actualizada.
// Útil cuando se cambia la configuración de DB de un tenant.
func (m *Manager) RefreshTenant(ctx context.Context, slug string) error {
	// 1. Limpiar cache del TDA (slug + UUID)
	m.clearTenantBySlug(slug)

	// 2. Cerrar conexión del pool (si existe)
	if m.factory != nil && m.factory.pool != nil {
		if err := m.factory.pool.Close(slug); err != nil {
			return fmt.Errorf("failed to close pool connection: %w", err)
		}
	}

	// La próxima llamada a ForTenant creará una nueva conexión
	return nil
}

// MigrateTenant ejecuta migraciones para un tenant específico.
func (m *Manager) MigrateTenant(ctx context.Context, slugOrID string) (*MigrationResult, error) {
	return m.factory.MigrateTenant(ctx, slugOrID)
}

// BootstrapResult contiene el resultado de hacer bootstrap de una DB de tenant.
type BootstrapResult struct {
	MigrationResult *MigrationResult // Resultado de migraciones SQL
	SyncedFields    []string         // Campos custom sincronizados
	Warnings        []string         // Warnings no fatales
	Error           error            // Error fatal (no se pudo conectar/migrar)
}

// BootstrapTenantDB inicializa la DB de un tenant: ejecuta migraciones y sincroniza custom fields.
// Retorna un BootstrapResult con info detallada. Si Error != nil, el bootstrap falló.
func (m *Manager) BootstrapTenantDB(ctx context.Context, slugOrID string) (result *BootstrapResult, err error) {
	result = &BootstrapResult{
		MigrationResult: &MigrationResult{}, // Initialize to avoid nil pointer
	}

	// Recover from panics
	defer func() {
		if r := recover(); r != nil {
			result.Error = fmt.Errorf("panic during bootstrap: %v", r)
			err = result.Error
		}
	}()

	// 1. Obtener TDA (esto conecta a la DB)
	tda, tdaErr := m.ForTenant(ctx, slugOrID)
	if tdaErr != nil {
		result.Error = fmt.Errorf("failed to connect to tenant DB: %w", tdaErr)
		return result, result.Error
	}

	// Verificar que tiene DB
	if !tda.HasDB() {
		result.Warnings = append(result.Warnings, "tenant has no database configured, skipping bootstrap")
		return result, nil // No es error, simplemente no hay DB
	}

	// 2. Ejecutar migraciones SQL
	migResult, migErr := m.MigrateTenant(ctx, slugOrID)
	if migResult != nil {
		result.MigrationResult = migResult
	}
	if migErr != nil {
		result.Error = fmt.Errorf("migration failed: %w", migErr)
		return result, result.Error
	}

	// 3. Sincronizar custom fields desde settings del tenant
	settings := tda.Settings()
	if settings != nil && len(settings.UserFields) > 0 {
		schema := tda.Schema()
		if schema != nil {
			// Convertir TenantSettings.UserFields a repository.UserFieldDefinition
			var fields []repository.UserFieldDefinition
			for _, f := range settings.UserFields {
				fields = append(fields, repository.UserFieldDefinition{
					Name:     f.Name,
					Type:     f.Type,
					Required: f.Required,
					Unique:   f.Unique,
					Indexed:  f.Indexed,
				})
				result.SyncedFields = append(result.SyncedFields, f.Name)
			}

			if syncErr := schema.SyncUserFields(ctx, tda.ID(), fields); syncErr != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("sync user fields partial error: %v", syncErr))
				// No retornamos error, solo warning
			}
		}
	}

	return result, nil
}

// Close cierra el manager y todas sus conexiones.
func (m *Manager) Close() error {
	return m.factory.Close()
}

// Ensure Manager implements DataAccessLayer
var _ DataAccessLayer = (*Manager)(nil)
