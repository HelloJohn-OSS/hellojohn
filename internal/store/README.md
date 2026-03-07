# Store V2 - Data Access Layer

Capa de acceso a datos unificada para `hellojohn`. Abstrae el almacenamiento subyacente (FileSystem, PostgreSQL, MySQL, MongoDB) detrás de interfaces de repositorio.

---

## Tabla de Contenidos

1. [Arquitectura General](#arquitectura-general)
2. [Modos de Operación](#modos-de-operación)
3. [Interfaces Principales](#interfaces-principales)
4. [Inicialización](#inicialización)
5. [Integración Profesional (Middleware)](#integración-profesional-middleware)
6. [Acceso a Datos](#acceso-a-datos)
7. [Adapters](#adapters)
8. [Connection Pool](#connection-pool)
9. [Cluster y Replicación](#cluster-y-replicación)
10. [Mejores Prácticas](#mejores-prácticas)
11. [Guía de Migración desde V1](#guía-de-migración-desde-v1)
12. [Errores Comunes](#errores-comunes)

---

## Arquitectura General

```
┌──────────────────────────────────────────────────────────────────┐
│                      HTTP Handlers / Services                    │
└───────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
┌──────────────────────────────────────────────────────────────────┐
│                     DataAccessLayer (Interface)                  │
│  - ForTenant(ctx, slugOrID) → TenantDataAccess                   │
│  - ConfigAccess() → ConfigAccess                                 │
│  - Mode(), Capabilities(), Stats()                               │
└───────────────────────────────┬──────────────────────────────────┘
                                │
             ┌──────────────────┴──────────────────┐
             ▼                                     ▼
┌───────────────────────────┐         ┌───────────────────────────┐
│       ConfigAccess        │         │     TenantDataAccess      │
│  (Control Plane - FS)     │         │    (Data Plane - DB)      │
│                           │         │                           │
│  • Tenants()              │         │  • Users()                │
│  • Clients(slug)          │         │  • Tokens()               │
│  • Scopes(slug)           │         │  • MFA()                  │
│                           │         │  • Consents()             │
│                           │         │  • Identities()           │
│                           │         │  • EmailTokens()          │
│                           │         │  • Cache()                │
└─────────────┬─────────────┘         └─────────────┬─────────────┘
              │                                     │
              ▼                                     ▼
┌───────────────────────────┐         ┌───────────────────────────┐
│      FS Adapter           │         │      PG Adapter           │
│  adapters/fs/             │         │      adapters/pg/         │
└───────────────────────────┘         └───────────────────────────┘
```

---

## Modos de Operación

El DAL detecta automáticamente su modo basándose en la configuración proporcionada.

| Modo | Código | Descripción | Control Plane | Data Plane |
|------|--------|-------------|---------------|------------|
| **FS Only** | `ModeFSOnly` | Solo FileSystem | ✅ FS | ❌ |
| **FS + Global DB** | `ModeFSGlobalDB` | FS + DB global para sync | ✅ FS | ⚠️ Global |
| **FS + Tenant DB** | `ModeFSTenantDB` | FS + DB por tenant | ✅ FS | ✅ Por tenant |
| **Full DB** | `ModeFullDB` | FS + Global + Tenant | ✅ FS | ✅ Ambos |

### Detección Automática

```go
mode := store.DetectMode(store.ModeConfig{
    FSRoot:          "./data/hellojohn",
    GlobalDB:        nil,                    // No hay DB global
    DefaultTenantDB: &store.DBConfig{...},   // Hay DB por tenant
})
// → mode = ModeFSTenantDB
```

### Capacidades por Modo

```go
caps := store.GetCapabilities(store.ModeFSTenantDB)
// caps.Tenants  = true  (siempre)
// caps.Clients  = true  (siempre)
// caps.Users    = true  (requiere TenantDB)
// caps.Tokens   = true  (requiere TenantDB)
// caps.MFA      = true  (requiere TenantDB)
```

---

## Interfaces Principales

### DataAccessLayer

Punto de entrada principal. Implementado por `Factory` y `Manager`.

```go
type DataAccessLayer interface {
    ForTenant(ctx, slugOrID) (TenantDataAccess, error)
    ConfigAccess() ConfigAccess
    Mode() OperationalMode
    Capabilities() ModeCapabilities
    MigrateTenant(ctx, slugOrID) (*MigrationResult, error)
    Stats() FactoryStats
    Close() error
}
```

### ConfigAccess

Acceso al Control Plane (siempre disponible via FS).

```go
type ConfigAccess interface {
    Tenants() repository.TenantRepository
    Clients(tenantSlug string) repository.ClientRepository
    Scopes(tenantSlug string) repository.ScopeRepository
}
```

### TenantDataAccess

Acceso a datos de un tenant específico.

```go
type TenantDataAccess interface {
    // Identificación
    Slug() string
    ID() string
    Settings() *repository.TenantSettings
    Driver() string
    
    // Data Plane (nil si no hay DB)
    Users() repository.UserRepository
    Tokens() repository.TokenRepository
    MFA() repository.MFARepository
    Consents() repository.ConsentRepository
    RBAC() repository.RBACRepository
    EmailTokens() repository.EmailTokenRepository
    Identities() repository.IdentityRepository
    Schema() repository.SchemaRepository
    
    // Control Plane (siempre disponible)
    Clients() repository.ClientRepository
    Scopes() repository.ScopeRepository
    
    // Infraestructura
    Cache() cache.Client
    CacheRepo() repository.CacheRepository
    HasDB() bool
    RequireDB() error
    InfraStats(ctx) (*TenantInfraStats, error)
}
```

---

## Inicialización

### Método 1: Factory (Recomendado)

```go
import storev2 "github.com/dropDatabas3/hellojohn/internal/store/v2"

factory, err := storev2.NewFactory(ctx, storev2.FactoryConfig{
    FSRoot: "./data/hellojohn",
    
    // Opcional: DB global para backup/sync
    GlobalDB: &storev2.DBConfig{
        Driver: "postgres",
        DSN:    "postgres://user:pass@host:5432/global",
    },
    
    // Opcional: DB default para tenants nuevos
    DefaultTenantDB: &storev2.DBConfig{
        Driver: "postgres",
        DSN:    "postgres://user:pass@host:5432/tenants",
    },
    
    // Opcional: Migraciones embebidas
    MigrationsFS:  migrationsFS,
    MigrationsDir: "migrations/tenant",
    
    // Opcional: Logger
    Logger: log.Default(),
})
defer factory.Close()
```

### Método 2: Manager (Con cache de TenantDataAccess)

```go
manager, err := storev2.NewManager(ctx, storev2.ManagerConfig{
    FSRoot:          "./data/hellojohn",
    DefaultTenantDB: &storev2.DBConfig{Driver: "postgres", DSN: "..."},
})
defer manager.Close()

// TenantDataAccess se cachea automáticamente
tda, _ := manager.ForTenant(ctx, "acme")
tda2, _ := manager.ForTenant(ctx, "acme") // Mismo objeto, desde cache
```

### Método 3: OpenAdapter (Bajo nivel)

Para acceso directo a un adapter específico.

```go
conn, err := storev2.OpenAdapter(ctx, storev2.AdapterConfig{
    Name:             "fs",
    FSRoot:           "./data/hellojohn",
    SigningMasterKey: os.Getenv("SIGNING_MASTER_KEY"),
})
defer conn.Close()

// Acceso directo a repositorios
tenants := conn.Tenants()
keys := conn.Keys()
```

---

## Integración Profesional (Middleware)

> **¿Por qué NO instanciar todos los tenants al inicio?**
> 
> Si tienes 10,000 tenants, el startup sería lentísimo. El patrón estándar es **Lazy Loading por Request** con inyección en Contexto.

### El Flujo Ideal

```
Request HTTP → Middleware (detecta tenant) → Context → Handler (usa repos)
```

1. **Global**: `store.Manager` se inicializa una sola vez en `main.go`
2. **Request**: Llega una petición HTTP
3. **Middleware**: Detecta el tenant, pide al Manager el acceso, guarda en `context`
4. **Handler**: Saca el acceso del `context` y lo usa

### Auto-Registro de Adapters

Para que los adapters se registren automáticamente, importa el paquete `dal`:

```go
import (
    store "github.com/dropDatabas3/hellojohn/internal/store/v2"
    _ "github.com/dropDatabas3/hellojohn/internal/store/v2/adapters/dal" // Auto-registra fs, pg, noop
)
```

### Middleware de Tenant

```go
// internal/http/middleware/tenant.go

type TenantMiddleware struct {
    manager *store.Manager
}

func (m *TenantMiddleware) Handle(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // 1. Detectar slug (header, subdominio, path)
        slug := r.Header.Get("X-Tenant-ID")
        if slug == "" {
            slug = extractFromSubdomain(r.Host) // o path
        }
        
        // 2. Obtener TenantDataAccess (cacheado internamente, microsegundos)
        tda, err := m.manager.ForTenant(r.Context(), slug)
        if err != nil {
            http.Error(w, "Tenant not found", http.StatusNotFound)
            return
        }
        
        // 3. Inyectar en contexto
        ctx := context.WithValue(r.Context(), tenantKey, tda)
        
        // 4. Continuar
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

### Helper para Handlers

```go
// internal/http/context.go

type ctxKey string
const tenantKey ctxKey = "tenant"

// GetTenant extrae TenantDataAccess del contexto
func GetTenant(ctx context.Context) (store.TenantDataAccess, error) {
    tda, ok := ctx.Value(tenantKey).(store.TenantDataAccess)
    if !ok {
        return nil, errors.New("no tenant in context")
    }
    return tda, nil
}

// MustGetTenant - panic si no hay tenant (para rutas que SIEMPRE tienen tenant)
func MustGetTenant(ctx context.Context) store.TenantDataAccess {
    tda, err := GetTenant(ctx)
    if err != nil {
        panic(err)
    }
    return tda
}
```

### Uso en Handler (Limpio)

```go
func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
    // El middleware ya resolvió el tenant
    tda, err := httpContext.GetTenant(r.Context())
    if err != nil {
        http.Error(w, "Internal error", 500)
        return
    }
    
    // Usar repositorios directamente
    user, _, err := tda.Users().Create(r.Context(), repository.CreateUserInput{
        TenantID: tda.ID(),
        Email:    req.Email,
    })
    
    // ...
}
```

### Beneficios

| Aspecto | Sin Middleware | Con Middleware |
|---------|----------------|----------------|
| **Startup** | Lento (carga todo) | Instantáneo |
| **Recursos** | Conexiones a DBs inactivas | Solo DBs activas |
| **Hot Reload** | Requiere reinicio | Cache invalida automáticamente |
| **Código Handler** | Mezclado con config | Limpio, solo lógica |

---

## Acceso a Datos

### Patrón: Acceso por Tenant

```go
// 1. Obtener acceso al tenant
tda, err := dal.ForTenant(ctx, "acme")
if err != nil {
    if store.IsTenantNotFound(err) {
        return errors.New("tenant no existe")
    }
    return err
}

// 2. Verificar si tiene DB (para operaciones de usuarios)
if !tda.HasDB() {
    return store.ErrNoDBForTenant
}

// 3. Usar repositorios
users := tda.Users()
user, identity, err := users.GetByEmail(ctx, tda.ID(), email)
```

### Patrón: Acceso a Config (Control Plane)

```go
config := dal.ConfigAccess()

// Listar tenants
tenants, err := config.Tenants().List(ctx)

// Obtener clients de un tenant
clients, err := config.Clients("acme").List(ctx, "acme", "")

// Obtener scopes
scopes, err := config.Scopes("acme").List(ctx, "acme")
```

### Patrón: Crear Usuario

```go
tda, _ := dal.ForTenant(ctx, "acme")
if err := tda.RequireDB(); err != nil {
    return err
}

users := tda.Users()
user, identity, err := users.Create(ctx, repository.CreateUserInput{
    TenantID:     tda.ID(),
    Email:        "john@example.com",
    PasswordHash: hashPassword("secret123"),
    Name:         "John Doe",
})
```

### Patrón: Check Null Repositories

```go
tda, _ := dal.ForTenant(ctx, "acme")

// Los repos de Data Plane pueden ser nil en modo FS-only
if users := tda.Users(); users != nil {
    // Seguro usar
    user, err := users.GetByID(ctx, userID)
}

// Los repos de Control Plane nunca son nil
clients := tda.Clients() // Siempre disponible
```

---

## Adapters

### FS Adapter (`adapters/fs/`)

**Soporta:** Control Plane (Tenants, Clients, Scopes, Keys)

| Repositorio | Implementado | Notas |
|-------------|--------------|-------|
| `TenantRepository` | ✅ | Lee/escribe `tenants/{slug}/tenant.yaml` |
| `ClientRepository` | ✅ | Lee/escribe `tenants/{slug}/clients.yaml` |
| `ScopeRepository` | ✅ | Lee/escribe `tenants/{slug}/scopes.yaml` |
| `KeyRepository` | ✅ | Lee/escribe `keys/active.json`, `keys/{tenant}/active.json` |
| `UserRepository` | ❌ | Retorna `nil` |
| `TokenRepository` | ❌ | Retorna `nil` |
| `MFARepository` | ❌ | Retorna `nil` |

**Estructura de archivos:**
```
data/hellojohn/
├── tenants/
│   ├── acme/
│   │   ├── tenant.yaml
│   │   ├── clients.yaml
│   │   └── scopes.yaml
│   └── local/
│       └── ...
└── keys/
    ├── active.json         # Clave global
    ├── retiring.json       # Clave en rotación
    └── acme/
        ├── active.json     # Clave del tenant
        └── retiring.json
```

### PG Adapter (`adapters/pg/`)

**Soporta:** Data Plane (Users, Tokens, MFA, Consents, etc.)

| Repositorio | Implementado | Tablas |
|-------------|--------------|--------|
| `UserRepository` | ✅ | `users`, `identities` |
| `TokenRepository` | ✅ | `refresh_tokens` |
| `MFARepository` | ✅ | `mfa_totp`, `mfa_recovery_codes`, `mfa_trusted_devices` |
| `ConsentRepository` | ✅ | `consents` |
| `RBACRepository` | ✅ | `user_roles`, `role_permissions` |
| `EmailTokenRepository` | ✅ | `email_tokens` |
| `IdentityRepository` | ✅ | `identities` (social) |
| `SchemaRepository` | ✅ | Dynamic SQL |

### MySQL Adapter (`adapters/mysql/`)

**Soporta:** Data Plane (Users, Tokens, MFA, Consents, etc.) - Alternativa a PostgreSQL

**Requisitos:**
- MySQL 8.0+
- Driver: `github.com/go-sql-driver/mysql`

**DSN Format:**
```
user:password@tcp(host:port)/database?parseTime=true&multiStatements=true
```

| Repositorio | Implementado | Notas |
|-------------|--------------|-------|
| `UserRepository` | ✅ | 12 métodos - `user.go` |
| `TokenRepository` | ✅ | 10 métodos - `token.go` |
| `SessionRepository` | ✅ | 10 métodos - `session.go` |
| `MFARepository` | ✅ | TOTP, recovery codes, trusted devices |
| `ConsentRepository` | ✅ | Scopes como JSON |
| `RBACRepository` | ✅ | Usa JSON_TABLE en lugar de UNNEST |
| `EmailTokenRepository` | ✅ | Verificación y reset |
| `IdentityRepository` | ✅ | Social identities |
| `ScopeRepository` | ✅ | OAuth2 scopes |
| `SchemaRepository` | ✅ | Column introspection |

**Configuración de Tenant:**
```yaml
# tenant.yaml
settings:
  user_db:
    driver: "mysql"
    dsn_enc: "encrypted_mysql_dsn_here"
```

**Diferencias con PostgreSQL:**

| Concepto | PostgreSQL | MySQL |
|----------|------------|-------|
| Arrays | `TEXT[]` nativo | `JSON` + funciones JSON |
| Case-insensitive | `ILIKE` | `LIKE` (collation ci) |
| UUID generation | `gen_random_uuid()` | `UUID()` o generado en Go |
| RETURNING | Soportado | No disponible |
| Timestamps | `TIMESTAMPTZ` | `DATETIME(6)` |
| IP addresses | `INET` | `VARCHAR(45)` |

**Migraciones:** `migrations/mysql/tenant/`
- `0001_init_up.sql` - Schema completo (14 tablas)
- `0002_add_user_language_up.sql`
- `0003_create_sessions_up.sql`
- `0004_rbac_schema_fix_up.sql`

### Noop Adapter (`adapters/noop/`)

**Para testing.** Retorna `ErrNotImplemented` para todo.

```go
conn, _ := storev2.OpenAdapter(ctx, storev2.AdapterConfig{Name: "noop"})
```

---

## Connection Pool

El `ConnectionPool` administra conexiones de DB por tenant.

### Características

- **Thread-safe:** Usa `sync.Map` + `singleflight`
- **Lazy creation:** Crea conexiones solo cuando se necesitan
- **Health checks:** Verifica conexiones periódicamente
- **Auto-cleanup:** Cierra conexiones idle

### Configuración

```go
pool := storev2.NewConnectionPool(factory, storev2.PoolConfig{
    MaxIdleTime:         30 * time.Minute,
    HealthCheckInterval: 5 * time.Minute,
    OnConnect: func(slug string, conn AdapterConnection) {
        log.Printf("Connected: %s (%s)", slug, conn.Name())
    },
    OnDisconnect: func(slug string) {
        log.Printf("Disconnected: %s", slug)
    },
})
```

### Estadísticas

```go
stats := factory.Stats()
// stats.Mode = "fs_tenant_db"
// stats.ActiveConns = 5
// stats.Connections = map[string]ConnectionStats{...}
```

---

## Cluster y Replicación

Para HA multi-nodo, el DAL soporta replicación via Raft.

### ClusterHook

```go
hook := factory.ClusterHook()

// Antes de mutar: verificar liderazgo
if err := hook.RequireLeaderForMutation(ctx); err != nil {
    return err // ErrNotLeader si somos follower
}

// Después de mutar: replicar
mutation := storev2.NewClientMutation(
    repository.MutationClientCreate,
    tenant.ID,
    client.ClientID,
    client,
)
index, err := hook.Apply(ctx, mutation)
```

### Tipos de Mutación

```go
const (
    MutationTenantCreate   = "tenant.create"
    MutationTenantUpdate   = "tenant.update"
    MutationTenantDelete   = "tenant.delete"
    MutationClientCreate   = "client.create"
    MutationClientUpdate   = "client.update"
    MutationClientDelete   = "client.delete"
    MutationScopeCreate    = "scope.create"
    MutationScopeDelete    = "scope.delete"
    MutationKeyRotate      = "key.rotate"
    MutationSettingsUpdate = "settings.update"
)
```

---

## Mejores Prácticas

### 1. Verificar DB Antes de Usar Data Plane

```go
// ❌ MAL - puede panic si no hay DB
users := tda.Users()
user, _ := users.GetByID(ctx, id)

// ✅ BIEN - verificación explícita
if err := tda.RequireDB(); err != nil {
    return store.ErrNoDBForTenant
}
user, _ := tda.Users().GetByID(ctx, id)

// ✅ TAMBIÉN BIEN - check nil
if users := tda.Users(); users != nil {
    user, _ := users.GetByID(ctx, id)
}
```

### 2. Reutilizar TenantDataAccess

```go
// ❌ MAL - llama ForTenant múltiples veces
user, _ := dal.ForTenant(ctx, slug).Users().GetByID(ctx, id)
tokens, _ := dal.ForTenant(ctx, slug).Tokens().GetByHash(ctx, hash)

// ✅ BIEN - obtener una vez, reutilizar
tda, _ := dal.ForTenant(ctx, slug)
user, _ := tda.Users().GetByID(ctx, id)
tokens, _ := tda.Tokens().GetByHash(ctx, hash)
```

### 3. Usar El Middleware Pattern

```go
// ❌ MAL - resolver tenant en cada handler
func (h *Handler) Create(w, r) {
    slug := r.Header.Get("X-Tenant-ID")
    tda, _ := h.dal.ForTenant(ctx, slug)
    // ...
}

// ✅ BIEN - middleware resuelve, handler solo usa
func (h *Handler) Create(w, r) {
    tda := httpContext.MustGetTenant(r.Context())
    // ...
}
```

### 4. Control Plane Siempre Disponible

```go
// Control Plane funciona incluso si no hay DB
tda, _ := dal.ForTenant(ctx, slug)

// Estos SIEMPRE funcionan (vía FS):
tda.Clients().List(ctx, slug, "")  // ✅
tda.Scopes().List(ctx, slug)       // ✅
tda.Settings()                      // ✅

// Estos pueden ser nil si no hay DB:
tda.Users()   // puede ser nil
tda.Tokens()  // puede ser nil
```

### 5. Invalidar Cache Cuando Cambia Config

```go
// Después de modificar un tenant
dal.ConfigAccess().Tenants().UpdateSettings(ctx, slug, settings)

// Invalidar cache del Manager para forzar recarga
if mgr, ok := dal.(*store.Manager); ok {
    mgr.ClearTenant(slug)
}
```

### 6. Manejar Errores Apropiadamente

```go
tda, err := dal.ForTenant(ctx, slug)
if err != nil {
    switch {
    case store.IsTenantNotFound(err):
        // 404 - tenant no existe
    case store.IsNoDBForTenant(err):
        // 503 - tenant sin DB
    default:
        // 500 - error interno
    }
}
```

### Resumen de Métodos por Adapter

| Adapter | ~Métodos | Repositorios |
|---------|----------|--------------|
| **fs** | 22 | Tenant, Client, Scope, Key |
| **pg** | 38 | User, Token, MFA, Consent, RBAC, EmailToken, Identity, Schema |
| **noop** | 38 | Todos (retorna `ErrNotImplemented`) |

---

## Guía de Migración desde V1

### Antes (V1 Handler)

```go
// Acceso mezclado a múltiples stores
user, err := c.Store.GetUserByEmail(ctx, email)
tenant, err := cpctx.Provider.GetTenantBySlug(ctx, slug)
client, err := c.Store.GetClientByClientID(ctx, clientID)
// ... lógica en el handler ...
```

### Después (V2 Service)

```go
// 1. Obtener DAL (inyectado en el service)
tda, err := s.dal.ForTenant(ctx, slug)
if err != nil {
    return err
}

// 2. Usar repositorios tipados
user, identity, err := tda.Users().GetByEmail(ctx, tda.ID(), email)
if repository.IsNotFound(err) {
    return ErrUserNotFound
}

// 3. Config siempre disponible
client, err := tda.Clients().Get(ctx, tda.ID(), clientID)
```

### Mapeo de Funciones V1 → V2

| V1 | V2 |
|----|------|
| `c.Store.GetUserByEmail(...)` | `tda.Users().GetByEmail(ctx, tenantID, email)` |
| `c.Store.CreateUser(...)` | `tda.Users().Create(ctx, input)` |
| `cpctx.Provider.GetTenantBySlug(...)` | `dal.ConfigAccess().Tenants().GetBySlug(ctx, slug)` |
| `c.Issuer.Keys.Active()` | `conn.Keys().GetActive(ctx, tenantID)` |
| `c.Cache.Get(...)` | `tda.CacheRepo().Get(ctx, key)` |

---

## Errores Comunes

### Errores del DAL

```go
var (
    ErrTenantNotFound // Tenant no existe en FS
    ErrNoDBForTenant  // Tenant no tiene DB configurada
    ErrNotLeader      // Operación requiere ser líder
)

// Helpers
store.IsTenantNotFound(err)
store.IsNoDBForTenant(err)
```

### Errores de Repository

Ver [domain/repository/README.md](../../../domain/repository/README.md):

```go
var (
    repository.ErrNotFound
    repository.ErrConflict
    repository.ErrInvalidInput
    repository.ErrNotImplemented
)
```

---

## Ejemplo Completo: Login Flow

```go
func (s *AuthService) Login(ctx context.Context, slug, email, password string) (*TokenPair, error) {
    // 1. Obtener acceso al tenant
    tda, err := s.dal.ForTenant(ctx, slug)
    if err != nil {
        return nil, err
    }
    
    // 2. Verificar que tiene DB
    if err := tda.RequireDB(); err != nil {
        return nil, err
    }
    
    // 3. Buscar usuario
    user, identity, err := tda.Users().GetByEmail(ctx, tda.ID(), email)
    if err != nil {
        if repository.IsNotFound(err) {
            return nil, ErrInvalidCredentials
        }
        return nil, err
    }
    
    // 4. Verificar password
    if !tda.Users().CheckPassword(identity.PasswordHash, password) {
        return nil, ErrInvalidCredentials
    }
    
    // 5. Verificar MFA si está habilitado
    if tda.Settings().MFAEnabled {
        mfa, err := tda.MFA().GetTOTP(ctx, user.ID)
        if err == nil && mfa.ConfirmedAt != nil {
            return nil, ErrMFARequired
        }
    }
    
    // 6. Crear tokens
    tokenID, err := tda.Tokens().Create(ctx, repository.CreateRefreshTokenInput{
        TenantID:   tda.ID(),
        ClientID:   clientID,
        UserID:     user.ID,
        TokenHash:  hash(refreshToken),
        TTLSeconds: 30 * 24 * 60 * 60,
    })
    
    return &TokenPair{
        AccessToken:  s.issuer.IssueAccess(...),
        RefreshToken: refreshToken,
    }, nil
}
```
