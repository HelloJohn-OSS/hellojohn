package store

import (
	"errors"
	"strings"
)

// OperationalMode define el modo de operación del Data Layer.
type OperationalMode int

// ModeInvalid es el valor cero (sentinel) que indica modo no inicializado.
const ModeInvalid OperationalMode = 0

const (
	// ModeFSOnly: Solo FileSystem. Sin base de datos.
	// Útil para: desarrollo, testing, tenants sin usuarios.
	// Capacidades: tenants, clients, scopes, admins, branding.
	// NO soporta: usuarios, tokens, MFA, consents.
	ModeFSOnly OperationalMode = iota + 1

	// ModeFSGlobalDB: FileSystem + DB Global.
	// La DB global almacena config como backup/sync del FS.
	// Útil para: clusters grandes que no quieren Raft.
	// Capacidades: todo de ModeFSOnly + backup en DB.
	ModeFSGlobalDB

	// ModeFSTenantDB: FileSystem + DB por Tenant.
	// Cada tenant tiene su propia base de datos para user data.
	// Útil para: SaaS multi-tenant con aislamiento fuerte.
	// Capacidades: todo de ModeFSOnly + users, tokens, MFA por tenant.
	ModeFSTenantDB

	// ModeFullDB: FileSystem + DB Global + DB por Tenant.
	// Máxima capacidad. Config en global, data en tenant.
	// Útil para: empresas grandes, compliance estricto.
	// Capacidades: todas.
	ModeFullDB

	// ModeFSGlobalDP: FileSystem + Global Data Plane.
	// Tenants sin DB propia almacenan user data en una DB compartida con logical isolation.
	// Útil para: HelloJohn Cloud, SaaS onboarding sin provisionar DB por tenant.
	// Capacidades: todo de ModeFSOnly + users/tokens/MFA/RBAC/consents via Global DP.
	ModeFSGlobalDP

	// ModeFullGlobalDP: FileSystem + Global CP DB + Global Data Plane.
	// Como ModeFSGlobalDP pero además sincroniza control plane en DB Global.
	// Útil para: clusters sin Raft que necesitan CP en DB + user data en GDP.
	ModeFullGlobalDP
)

// String retorna nombre legible del modo.
func (m OperationalMode) String() string {
	switch m {
	case ModeFSOnly:
		return "fs_only"
	case ModeFSGlobalDB:
		return "fs_global_db"
	case ModeFSTenantDB:
		return "fs_tenant_db"
	case ModeFullDB:
		return "full_db"
	case ModeFSGlobalDP:
		return "fs_global_dp"
	case ModeFullGlobalDP:
		return "full_global_dp"
	default:
		return "unknown"
	}
}

// Description retorna descripción del modo.
func (m OperationalMode) Description() string {
	switch m {
	case ModeFSOnly:
		return "Solo FileSystem (sin DB)"
	case ModeFSGlobalDB:
		return "FileSystem + DB Global"
	case ModeFSTenantDB:
		return "FileSystem + DB por Tenant"
	case ModeFullDB:
		return "FileSystem + DB Global + DB por Tenant"
	case ModeFSGlobalDP:
		return "FileSystem + Global Data Plane"
	case ModeFullGlobalDP:
		return "FileSystem + DB Global + Global Data Plane"
	default:
		return "Modo desconocido"
	}
}

// SupportsUsers indica si el modo soporta operaciones de usuarios.
func (m OperationalMode) SupportsUsers() bool {
	return m == ModeFSTenantDB || m == ModeFullDB ||
		m == ModeFSGlobalDP || m == ModeFullGlobalDP
}

// SupportsGlobalDP indica si el modo usa Global Data Plane (shared DB con RLS).
func (m OperationalMode) SupportsGlobalDP() bool {
	return m == ModeFSGlobalDP || m == ModeFullGlobalDP
}

// SupportsGlobalDB indica si hay DB global disponible.
func (m OperationalMode) SupportsGlobalDB() bool {
	return m == ModeFSGlobalDB || m == ModeFullDB
}

// SupportsTenantDB indica si soporta DB por tenant.
func (m OperationalMode) SupportsTenantDB() bool {
	return m == ModeFSTenantDB || m == ModeFullDB
}

// ModeConfig configuración para detectar el modo.
type ModeConfig struct {
	// FSRoot path al directorio del control plane (requerido).
	FSRoot string

	// GlobalDB configuración de DB global (opcional).
	GlobalDB *DBConfig

	// DefaultTenantDB configuración default para tenants nuevos (opcional).
	DefaultTenantDB *DBConfig

	// GlobalDataPlaneDB configuración del Global Data Plane (opcional).
	GlobalDataPlaneDB *DBConfig
}

// DBConfig configuración de base de datos.
type DBConfig struct {
	Driver string // postgres, mysql, mongo
	DSN    string
	Schema string // para multi-schema en misma DB

	// Pool settings
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime string // e.g. "5m"
}

// Valid verifica si la config de DB es válida.
func (c *DBConfig) Valid() bool {
	if c == nil {
		return false
	}
	return strings.TrimSpace(c.Driver) != "" && strings.TrimSpace(c.DSN) != ""
}

// ErrInvalidModeConfig is returned (as a sentinel) by DetectMode when the
// caller has configured GlobalDataPlaneDB and DefaultTenantDB simultaneously.
// These two modes are mutually exclusive: GlobalDP uses a single shared DB
// with RLS, while TenantDB uses one isolated DB per tenant.
var ErrInvalidModeConfig = errors.New("store: GlobalDataPlaneDB and DefaultTenantDB cannot be used simultaneously")

// DetectMode detecta automáticamente el modo operacional.
//
// Reglas:
//   - Si hay GlobalDB Y DefaultTenantDB → ModeFullDB
//   - Si solo hay DefaultTenantDB → ModeFSTenantDB
//   - Si solo hay GlobalDB → ModeFSGlobalDB
//   - Sin ninguna DB → ModeFSOnly
//
// Returns 0 (ModeInvalid) when GlobalDataPlaneDB and DefaultTenantDB are both
// set. The caller should treat this return value as an error and check the
// sentinel ErrInvalidModeConfig (the signature does not return an error for
// backward compatibility; callers should use DetectModeStrict for full error
// propagation).
func DetectMode(cfg ModeConfig) OperationalMode {
	hasGlobal := cfg.GlobalDB.Valid()
	hasTenantDefault := cfg.DefaultTenantDB.Valid()
	hasGlobalDP := cfg.GlobalDataPlaneDB.Valid()

	// GlobalDataPlaneDB y DefaultTenantDB son modos mutuamente excluyentes.
	// GlobalDP usa una sola DB compartida con RLS; TenantDB usa una DB aislada por tenant.
	// Configurar ambos simultáneamente es probablemente un error del operador.
	if hasGlobalDP && hasTenantDefault {
		// No podemos retornar error aquí (func devuelve OperationalMode),
		// retornamos 0 (modo inválido) para que el caller lo detecte.
		return 0
	}

	switch {
	case hasGlobal && hasTenantDefault:
		return ModeFullDB
	case !hasGlobal && hasTenantDefault:
		return ModeFSTenantDB
	case hasGlobal && hasGlobalDP && !hasTenantDefault:
		return ModeFullGlobalDP
	case !hasGlobal && hasGlobalDP && !hasTenantDefault:
		return ModeFSGlobalDP
	case hasGlobal && !hasTenantDefault:
		return ModeFSGlobalDB
	default:
		return ModeFSOnly
	}
}

// ParseMode parsea un string a OperationalMode.
func ParseMode(s string) OperationalMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "fs_only", "fs-only", "1":
		return ModeFSOnly
	case "fs_global_db", "fs-global-db", "2":
		return ModeFSGlobalDB
	case "fs_tenant_db", "fs-tenant-db", "3":
		return ModeFSTenantDB
	case "full_db", "full-db", "4":
		return ModeFullDB
	case "fs_global_dp", "fs-global-dp", "5":
		return ModeFSGlobalDP
	case "full_global_dp", "full-global-dp", "6":
		return ModeFullGlobalDP
	default:
		return 0 // inválido
	}
}

// ModeCapabilities describe las capacidades de cada modo.
type ModeCapabilities struct {
	Mode OperationalMode

	// Config operations (siempre disponibles con FS)
	Tenants  bool
	Clients  bool
	Scopes   bool
	Admins   bool
	Branding bool

	// Data operations (requieren DB)
	Users    bool
	Tokens   bool
	MFA      bool
	Consents bool
	RBAC     bool

	// Infra
	GlobalDBSync bool
	TenantDB     bool
	Cache        bool
	GlobalDP     bool // True si se usa Global Data Plane (shared DB con RLS)
}

// GetCapabilities retorna las capacidades del modo.
func GetCapabilities(mode OperationalMode) ModeCapabilities {
	caps := ModeCapabilities{
		Mode: mode,
		// Config siempre disponible (FS)
		Tenants:  true,
		Clients:  true,
		Scopes:   true,
		Admins:   true,
		Branding: true,
		// Cache siempre disponible (al menos memory)
		Cache: true,
	}

	switch mode {
	case ModeFSGlobalDB:
		caps.GlobalDBSync = true
	case ModeFSTenantDB:
		caps.TenantDB = true
		caps.Users = true
		caps.Tokens = true
		caps.MFA = true
		caps.Consents = true
		caps.RBAC = true
	case ModeFullDB:
		caps.GlobalDBSync = true
		caps.TenantDB = true
		caps.Users = true
		caps.Tokens = true
		caps.MFA = true
		caps.Consents = true
		caps.RBAC = true
	case ModeFSGlobalDP:
		caps.GlobalDP = true
		caps.Users = true
		caps.Tokens = true
		caps.MFA = true
		caps.Consents = true
		caps.RBAC = true
	case ModeFullGlobalDP:
		caps.GlobalDBSync = true
		caps.GlobalDP = true
		caps.Users = true
		caps.Tokens = true
		caps.MFA = true
		caps.Consents = true
		caps.RBAC = true
	}

	return caps
}
