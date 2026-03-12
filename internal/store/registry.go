// Package store provee el registry de adaptadores de base de datos.
package store

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/google/uuid"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// Adapter representa un adaptador de base de datos capaz de crear repositorios.
type Adapter interface {
	// Name retorna el nombre del adapter (ej: "postgres", "mysql", "mongo", "fs").
	Name() string

	// Connect establece conexión con el almacenamiento.
	Connect(ctx context.Context, cfg AdapterConfig) (AdapterConnection, error)
}

// AdapterConnection representa una conexión activa.
// Provee acceso a los repositorios implementados por el adapter.
type AdapterConnection interface {
	// Name retorna el nombre del adapter.
	Name() string

	// Ping verifica la conexión.
	Ping(ctx context.Context) error

	// Close cierra la conexión.
	Close() error

	// ─── Data Plane Repositorios (nil si no soportado por el adapter) ───

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

	// ─── Control Plane (solo para adapter fs, acceso via fsRawConnection) ───

	Tenants() repository.TenantRepository
	SystemSettings() repository.SystemSettingsRepository
	Admins() repository.AdminRepository
	AdminRefreshTokens() repository.AdminRefreshTokenRepository
	Keys() repository.KeyRepository
	APIKeys() repository.APIKeyRepository

	// ─── Cloud Control Plane ───
	CloudUsers() repository.CloudUserRepository
	CloudInstances() repository.CloudInstanceRepository
}

// MigratableConnection interfaz opcional para conexiones que pueden ejecutar migraciones.
// Las conexiones de DB (postgres, mysql) deben implementar esto.
type MigratableConnection interface {
	// GetMigrationExecutor retorna el ejecutor para migraciones (pgxpool, etc).
	GetMigrationExecutor() PgxPoolExecutor
}

// AdapterConfig configuración para conectar a un almacenamiento.
type AdapterConfig struct {
	// Name del adapter: "postgres", "mysql", "mongo", "fs"
	Name string

	// DSN connection string (para DBs)
	DSN string

	// FSRoot path al directorio raíz (para fs adapter)
	FSRoot string

	// Schema/database name (opcional, para multi-tenant en misma DB)
	Schema string

	// Pool settings (para DBs)
	MaxOpenConns int
	MaxIdleConns int

	// MigrationsDir directorio de migraciones (opcional)
	MigrationsDir string

	// SigningMasterKey para encriptar/desencriptar claves de firma (hex, 64 chars)
	// Requerido para fs adapter con KeyRepository
	SigningMasterKey string
}

// ─── Registry Global ───

var (
	registryMu sync.RWMutex
	adapters   = make(map[string]Adapter)
)

// RegisterAdapter registra un adapter en el registry global.
// Llamar en init() de cada adapter.
func RegisterAdapter(a Adapter) {
	registryMu.Lock()
	defer registryMu.Unlock()

	name := a.Name()
	if _, exists := adapters[name]; exists {
		panic(fmt.Sprintf("adapter: %q already registered", name))
	}
	adapters[name] = a
}

// GetAdapter obtiene un adapter por nombre.
func GetAdapter(name string) (Adapter, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	a, ok := adapters[name]
	return a, ok
}

// ListAdapters retorna los nombres de todos los adapters registrados.
func ListAdapters() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	names := make([]string, 0, len(adapters))
	for name := range adapters {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// OpenAdapter abre una conexión usando el adapter especificado en la config.
func OpenAdapter(ctx context.Context, cfg AdapterConfig) (AdapterConnection, error) {
	a, ok := GetAdapter(cfg.Name)
	if !ok {
		return nil, fmt.Errorf("adapter: %q not registered", cfg.Name)
	}
	return a.Connect(ctx, cfg)
}

// TenantScopedConnection es implementado por adapters con aislamiento lógico de tenant.
// El pool base es compartido; ForTenant() retorna una conexión con tenantID fijo
// en todos los repositorios.
//
// Implementado por: pg_shared adapter (Global Data Plane).
// El Factory usa esta interface para crear conexiones del Global Data Plane.
type TenantScopedConnection interface {
	// ForTenant retorna una AdapterConnection con tenantID baked in.
	// Todos los repos de la conexión resultante operan exclusivamente en ese tenant.
	ForTenant(tenantID uuid.UUID) AdapterConnection
}
