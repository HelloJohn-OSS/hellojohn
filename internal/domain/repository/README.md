# Paquete `internal/domain/repository` - Documentación Completa

Interfaces de repositorio que definen contratos de negocio, independientes del almacenamiento subyacente.

---

## Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│              Services / Controllers / Handlers              │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                 domain/repository (interfaces)              │
│   UserRepository, ClientRepository, TokenRepository, etc.   │
└─────────────────────────────────────────────────────────────┘
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
      ┌──────────┐   ┌──────────┐   ┌──────────┐
      │ adapters/│   │ adapters/│   │ adapters/│
      │    pg    │   │    fs    │   │   noop   │
      └──────────┘   └──────────┘   └──────────┘
```

---

## Convenciones

- `Context` siempre es el primer parámetro
- `TenantID` se pasa explícitamente en métodos que lo requieren
- Errores de dominio definidos en `errors.go`
- Los métodos retornan `ErrNotFound` cuando el recurso no existe

---

## Índice de Repositorios

| Repositorio | Archivo | Plano | Descripción |
|-------------|---------|-------|-------------|
| `UserRepository` | user.go | Data | Usuarios y credentials |
| `TokenRepository` | token.go | Data | Refresh tokens |
| `TenantRepository` | tenant.go | Control | Tenants y settings |
| `ClientRepository` | client.go | Control | OIDC clients |
| `KeyRepository` | key.go | Control | Claves de firma |
| `MFARepository` | mfa.go | Data | TOTP y recovery codes |
| `ConsentRepository` | consent.go | Data | User consents |
| `ScopeRepository` | scope.go | Control | OAuth scopes |
| `RBACRepository` | rbac.go | Data | Roles y permisos |
| `IdentityRepository` | identity.go | Data | Identidades sociales |
| `EmailTokenRepository` | email_token.go | Data | Tokens de verificación |
| `SchemaRepository` | schema.go | Data | Schema dinámico |
| `ClusterRepository` | cluster.go | Infra | Replicación Raft |
| `CacheRepository` | cache.go | Infra | Cache (Redis/Memory) |

---

## Errores Comunes

```go
var (
    ErrNotFound          // Recurso no existe
    ErrConflict          // Duplicado o constraint violation
    ErrInvalidInput      // Datos inválidos
    ErrNotImplemented    // Driver no soporta operación
    ErrNoDatabase        // No hay DB configurada
    ErrUnauthorized      // Operación no autorizada
    ErrTokenExpired      // Token expiró
    ErrNotLeader         // Requiere ser líder del cluster
    ErrClusterUnavailable // Cluster no disponible
    ErrLastIdentity      // No se puede eliminar última identidad
)

// Helpers
func IsNotFound(err error) bool
func IsConflict(err error) bool
func IsNoDatabase(err error) bool
```

---

## 1. UserRepository

### Tipos

```go
type User struct {
    ID             string
    TenantID       string
    Email          string
    EmailVerified  bool
    Name           string
    GivenName      string
    FamilyName     string
    Picture        string
    Locale         string
    Metadata       map[string]any
    CustomFields   map[string]any
    CreatedAt      time.Time
    DisabledAt     *time.Time
    DisabledUntil  *time.Time
    DisabledReason *string
    SourceClientID *string
}

type Identity struct {
    ID             string
    UserID         string
    Provider       string // "password", "google"
    ProviderUserID string
    Email          string
    EmailVerified  bool
    PasswordHash   *string
    CreatedAt      time.Time
}

type CreateUserInput struct {
    TenantID, Email, PasswordHash string
    Name, GivenName, FamilyName   string
    Picture, Locale               string
    CustomFields                  map[string]any
    SourceClientID                string
}

type UpdateUserInput struct {
    Name, GivenName, FamilyName *string
    Picture, Locale             *string
    CustomFields                map[string]any
}

type ListUsersFilter struct {
    Limit  int    // Default 50, max 200
    Offset int
    Search string // Por email o nombre
}
```

### Métodos

| Método | Descripción | Retorna |
|--------|-------------|---------|
| `GetByEmail(ctx, tenantID, email)` | Busca por email | `(*User, *Identity, error)` |
| `GetByID(ctx, userID)` | Busca por UUID | `(*User, error)` |
| `List(ctx, tenantID, filter)` | Lista con paginación | `([]User, error)` |
| `Create(ctx, input)` | Crea usuario + identity | `(*User, *Identity, error)` |
| `Update(ctx, userID, input)` | Actualiza campos | `error` |
| `Delete(ctx, userID)` | Elimina usuario | `error` |
| `Disable(ctx, userID, by, reason, until)` | Deshabilita temporalmente | `error` |
| `Enable(ctx, userID, by)` | Rehabilita | `error` |
| `CheckPassword(hash, password)` | Verifica argon2id (PHC) | `bool` |
| `SetEmailVerified(ctx, userID, verified)` | Marca email verificado | `error` |
| `UpdatePasswordHash(ctx, userID, newHash)` | Cambia password | `error` |
| `ListPasswordHistory(ctx, userID, limit)` | Lista hashes recientes para `maxHistory` | `[]string, error` |
| `RotatePasswordHash(ctx, userID, newHash, keepHistory)` | Rota hash y persiste historial atómicamente | `error` |

---

## 2. TokenRepository

### Tipos

```go
type RefreshToken struct {
    ID          string
    UserID      string
    TenantID    string
    ClientID    string // client_id público
    TokenHash   string
    IssuedAt    time.Time
    ExpiresAt   time.Time
    RotatedFrom *string
    RevokedAt   *time.Time
}

type CreateRefreshTokenInput struct {
    TenantID, ClientID, UserID string
    TokenHash                  string
    TTLSeconds                 int
}
```

### Métodos

| Método | Descripción | Retorna |
|--------|-------------|---------|
| `Create(ctx, input)` | Crea refresh token | `(tokenID, error)` |
| `GetByHash(ctx, hash)` | Busca por hash | `(*RefreshToken, error)` |
| `Revoke(ctx, tokenID)` | Revoca por ID | `error` |
| `RevokeAllByUser(ctx, userID, clientID)` | Revoca todos de usuario | `(count, error)` |
| `RevokeAllByClient(ctx, clientID)` | Revoca todos de client | `error` |

---

## 3. TenantRepository

### Tipos

```go
type Tenant struct {
    ID, Slug, Name, DisplayName string
    Settings                    TenantSettings
    CreatedAt, UpdatedAt        time.Time
}

type TenantSettings struct {
    LogoURL, BrandColor         string
    SessionLifetimeSeconds      int
    RefreshTokenLifetimeSeconds int
    MFAEnabled, SocialLoginEnabled bool
    SMTP                        *SMTPSettings
    UserDB                      *UserDBSettings
    Cache                       *CacheSettings
    Security                    *SecurityPolicy
    UserFields                  []UserFieldDefinition
    Mailing                     *MailingSettings
    IssuerMode, IssuerOverride  string
}

type SMTPSettings struct {
    Host, Username, Password string
    Port                     int
    PasswordEnc, FromEmail   string
    UseTLS                   bool
}

type UserDBSettings struct {
    Driver, DSN, DSNEnc, Schema string
}

type CacheSettings struct {
    Enabled            bool
    Driver, Host       string
    Port, DB           int
    Password, PassEnc  string
    Prefix             string
}

type UserFieldDefinition struct {
    Name, Type, Description string
    Required, Unique, Indexed bool
}
```

### Métodos

| Método | Descripción | Retorna |
|--------|-------------|---------|
| `List(ctx)` | Lista todos los tenants | `([]Tenant, error)` |
| `GetBySlug(ctx, slug)` | Busca por slug | `(*Tenant, error)` |
| `GetByID(ctx, id)` | Busca por UUID | `(*Tenant, error)` |
| `Create(ctx, tenant)` | Crea tenant | `error` |
| `Update(ctx, tenant)` | Actualiza tenant | `error` |
| `Delete(ctx, slug)` | Elimina tenant | `error` |
| `UpdateSettings(ctx, slug, settings)` | Actualiza solo settings | `error` |

---

## 4. ClientRepository

### Tipos

```go
type Client struct {
    ID, TenantID, ClientID, Name, Type string
    RedirectURIs, AllowedOrigins       []string
    Providers, Scopes                  []string
    SecretEnc                          string
    RequireEmailVerification           bool
    ResetPasswordURL, VerifyEmailURL   string
    ClaimSchema, ClaimMapping          map[string]any
}

type ClientInput struct {
    Name, ClientID, Type        string
    RedirectURIs, AllowedOrigins []string
    Providers, Scopes           []string
    Secret                      string // Plain, se cifra
    RequireEmailVerification    bool
    ResetPasswordURL, VerifyEmailURL string
    ClaimSchema, ClaimMapping   map[string]any
}
```

### Métodos

| Método | Descripción | Retorna |
|--------|-------------|---------|
| `Get(ctx, tenantID, clientID)` | Por client_id público | `(*Client, error)` |
| `GetByUUID(ctx, uuid)` | Por UUID interno | `(*Client, *ClientVersion, error)` |
| `List(ctx, tenantID, query)` | Lista con filtro | `([]Client, error)` |
| `Create(ctx, tenantID, input)` | Crea client | `(*Client, error)` |
| `Update(ctx, tenantID, input)` | Actualiza client | `(*Client, error)` |
| `Delete(ctx, tenantID, clientID)` | Elimina client | `error` |
| `DecryptSecret(ctx, tenantID, clientID)` | Descifra secret | `(string, error)` |
| `ValidateClientID(id)` | Valida formato | `bool` |
| `ValidateRedirectURI(uri)` | Valida URI | `bool` |
| `IsScopeAllowed(client, scope)` | Verifica scope | `bool` |

---

## 5. KeyRepository

### Tipos

```go
type SigningKey struct {
    ID        string    // KID
    TenantID  string    // "" = global
    Algorithm string    // "EdDSA", "ES256", "RS256"
    PrivateKey, PublicKey any
    Status    KeyStatus // "active", "retired", "revoked"
    CreatedAt time.Time
    ExpiresAt, RetiredAt *time.Time
}

type KeyStatus string
const (
    KeyStatusActive  KeyStatus = "active"
    KeyStatusRetired KeyStatus = "retired"
    KeyStatusRevoked KeyStatus = "revoked"
)

type JWK struct {
    KID, Kty, Use, Alg, Crv string
    X, Y, N, E              string // Según algoritmo
    ExpiresAt               *int64
}

type JWKS struct {
    Keys []JWK `json:"keys"`
}
```

### Métodos

| Método | Descripción | Retorna |
|--------|-------------|---------|
| `GetActive(ctx, tenantID)` | Clave activa para firmar | `(*SigningKey, error)` |
| `GetByKID(ctx, kid)` | Busca por Key ID | `(*SigningKey, error)` |
| `GetJWKS(ctx, tenantID)` | JWKS (active + retired) | `(*JWKS, error)` |
| `Generate(ctx, tenantID, algorithm)` | Genera nuevo par | `(*SigningKey, error)` |
| `Rotate(ctx, tenantID, gracePeriod)` | Rota claves | `(*SigningKey, error)` |
| `Revoke(ctx, kid)` | Revoca inmediatamente | `error` |
| `ToEdDSA(key)` | Convierte a ed25519 | `(ed25519.PrivateKey, error)` |
| `ToECDSA(key)` | Convierte a ECDSA | `(*ecdsa.PrivateKey, error)` |

---

## 6. MFARepository

### Tipos

```go
type MFATOTP struct {
    UserID          string
    SecretEncrypted string
    ConfirmedAt     *time.Time
    LastUsedAt      *time.Time
    CreatedAt, UpdatedAt time.Time
}
```

### Métodos

| Método | Descripción | Retorna |
|--------|-------------|---------|
| `UpsertTOTP(ctx, userID, secretEnc)` | Crea/actualiza secreto | `error` |
| `ConfirmTOTP(ctx, userID)` | Marca como confirmado | `error` |
| `GetTOTP(ctx, userID)` | Obtiene config | `(*MFATOTP, error)` |
| `UpdateTOTPUsedAt(ctx, userID)` | Actualiza último uso | `error` |
| `DisableTOTP(ctx, userID)` | Deshabilita MFA | `error` |
| `SetRecoveryCodes(ctx, userID, hashes)` | Reemplaza recovery codes | `error` |
| `DeleteRecoveryCodes(ctx, userID)` | Elimina todos | `error` |
| `UseRecoveryCode(ctx, userID, hash)` | Marca code usado | `(bool, error)` |
| `AddTrustedDevice(ctx, userID, deviceHash, expiresAt)` | Añade dispositivo | `error` |
| `IsTrustedDevice(ctx, userID, deviceHash)` | Verifica dispositivo | `(bool, error)` |

---

## 7. ConsentRepository

### Tipos

```go
type Consent struct {
    ID, UserID, ClientID, TenantID string
    Scopes                         []string
    GrantedAt, UpdatedAt           time.Time
    RevokedAt                      *time.Time
}
```

### Métodos

| Método | Descripción | Retorna |
|--------|-------------|---------|
| `Upsert(ctx, tenantID, userID, clientID, scopes)` | Crea/actualiza | `(*Consent, error)` |
| `Get(ctx, tenantID, userID, clientID)` | Obtiene consent | `(*Consent, error)` |
| `ListByUser(ctx, tenantID, userID, activeOnly)` | Lista por usuario | `([]Consent, error)` |
| `Revoke(ctx, tenantID, userID, clientID)` | Revoca (soft delete) | `error` |

---

## 8. ScopeRepository

### Tipos

```go
type Scope struct {
    ID, TenantID, Name, Description string
    System                          bool // true para built-in
    CreatedAt                       time.Time
}
```

### Métodos

| Método | Descripción | Retorna |
|--------|-------------|---------|
| `Create(ctx, tenantID, name, description)` | Crea scope | `(*Scope, error)` |
| `GetByName(ctx, tenantID, name)` | Busca por nombre | `(*Scope, error)` |
| `List(ctx, tenantID)` | Lista todos | `([]Scope, error)` |
| `UpdateDescription(ctx, tenantID, scopeID, desc)` | Actualiza descripción | `error` |
| `Delete(ctx, tenantID, scopeID)` | Elimina scope | `error` |
| `Upsert(ctx, tenantID, name, description)` | Crea o actualiza | `(*Scope, error)` |

---

## 9. RBACRepository

### Métodos

| Método | Descripción | Retorna |
|--------|-------------|---------|
| `GetUserRoles(ctx, userID)` | Roles de usuario | `([]string, error)` |
| `GetUserPermissions(ctx, userID)` | Permisos efectivos | `([]string, error)` |
| `AssignRole(ctx, tenantID, userID, role)` | Asigna rol | `error` |
| `RemoveRole(ctx, tenantID, userID, role)` | Quita rol | `error` |
| `GetRolePermissions(ctx, tenantID, role)` | Permisos del rol | `([]string, error)` |
| `AddPermissionToRole(ctx, tenantID, role, perm)` | Añade permiso | `error` |
| `RemovePermissionFromRole(ctx, tenantID, role, perm)` | Quita permiso | `error` |

---

## 10. IdentityRepository

### Tipos

```go
type SocialIdentity struct {
    ID, UserID, TenantID         string
    Provider, ProviderUserID     string
    Email, Name, Picture         string
    EmailVerified                bool
    RawClaims                    map[string]any
    CreatedAt, UpdatedAt         time.Time
}

type UpsertSocialIdentityInput struct {
    TenantID, Provider, ProviderUserID string
    Email, Name, Picture               string
    EmailVerified                      bool
    RawClaims                          map[string]any
}
```

### Métodos

| Método | Descripción | Retorna |
|--------|-------------|---------|
| `GetByProvider(ctx, tenantID, provider, providerUserID)` | Busca identidad | `(*SocialIdentity, error)` |
| `GetByUserID(ctx, userID)` | Lista identidades | `([]SocialIdentity, error)` |
| `Upsert(ctx, input)` | Crea o actualiza | `(userID, isNew, error)` |
| `Link(ctx, userID, input)` | Vincula a usuario | `(*SocialIdentity, error)` |
| `Unlink(ctx, userID, provider)` | Elimina identidad | `error` |
| `UpdateClaims(ctx, identityID, claims)` | Actualiza claims | `error` |

---

## 11. EmailTokenRepository

### Tipos

```go
type EmailToken struct {
    ID, TenantID, UserID, Email string
    Type                        EmailTokenType
    TokenHash                   string
    ExpiresAt                   time.Time
    UsedAt                      *time.Time
    CreatedAt                   time.Time
}

type EmailTokenType string
const (
    EmailTokenVerification  EmailTokenType = "email_verification"
    EmailTokenPasswordReset EmailTokenType = "password_reset"
)

type CreateEmailTokenInput struct {
    TenantID, UserID, Email string
    Type                    EmailTokenType
    TokenHash               string
    TTLSeconds              int
}
```

### Métodos

| Método | Descripción | Retorna |
|--------|-------------|---------|
| `Create(ctx, input)` | Crea token | `(*EmailToken, error)` |
| `GetByHash(ctx, tokenHash)` | Busca por hash | `(*EmailToken, error)` |
| `Use(ctx, tokenHash)` | Marca como usado | `error` |
| `DeleteExpired(ctx)` | Limpia expirados | `(count, error)` |

---

## 12. SchemaRepository

### Tipos

```go
type ColumnInfo struct {
    Name, DataType string
    IsNullable     bool
    Default        string
}
```

### Métodos

| Método | Descripción | Retorna |
|--------|-------------|---------|
| `SyncUserFields(ctx, tenantID, fields)` | Sincroniza columnas | `error` |
| `EnsureIndexes(ctx, tenantID, schemaDef)` | Crea índices | `error` |
| `IntrospectColumns(ctx, tenantID, tableName)` | Lista columnas | `([]ColumnInfo, error)` |

---

## 13. ClusterRepository

### Tipos

```go
type ClusterNode struct {
    ID, Address       string
    Role              ClusterRole    // leader, follower, candidate
    State             ClusterNodeState // healthy, degraded, unreachable
    JoinedAt, LastSeen time.Time
    Latency           time.Duration
}

type ClusterStats struct {
    NodeID, LeaderID        string
    Role                    ClusterRole
    Term, CommitIndex, AppliedIndex uint64
    NumPeers                int
    Healthy                 bool
}

type Mutation struct {
    Type      MutationType // tenant.create, client.update, etc.
    TenantID, Key string
    Payload       []byte
    Timestamp     time.Time
}
```

### Métodos

| Método | Descripción | Retorna |
|--------|-------------|---------|
| `GetStats(ctx)` | Estadísticas del cluster | `(*ClusterStats, error)` |
| `IsLeader(ctx)` | ¿Este nodo es líder? | `(bool, error)` |
| `GetLeaderID(ctx)` | ID del líder actual | `(string, error)` |
| `GetPeers(ctx)` | Lista nodos | `([]ClusterNode, error)` |
| `Apply(ctx, mutation)` | Aplica mutación | `(index, error)` |
| `ApplyBatch(ctx, mutations)` | Aplica batch | `(lastIndex, error)` |
| `WaitForApply(ctx, targetIndex, timeout)` | Espera replicación | `error` |
| `AddPeer(ctx, id, address)` | Agrega nodo | `error` |
| `RemovePeer(ctx, id)` | Elimina nodo | `error` |
| `Ping(ctx)` | Verifica cluster | `error` |
| `Close()` | Cierra conexiones | `error` |

---

## 14. CacheRepository

### Tipos

```go
type CacheStats struct {
    Hits, Misses, Keys, MemoryUsed int64
    Latency                        time.Duration
}

// Prefijos estándar
const (
    CacheKeyPrefixSession      = "sid:"
    CacheKeyPrefixMFAChallenge = "mfa:token:"
    CacheKeyPrefixAuthCode     = "code:"
    CacheKeyPrefixSocialCode   = "social:code:"
    CacheKeyPrefixConsentToken = "consent:"
    CacheKeyPrefixRateLimit    = "rl:"
    CacheKeyPrefixJWKS         = "jwks:"
)
```

### Métodos

| Método | Descripción | Retorna |
|--------|-------------|---------|
| `Get(ctx, key)` | Obtiene valor | `([]byte, bool)` |
| `Set(ctx, key, value, ttl)` | Almacena con TTL | `error` |
| `Delete(ctx, key)` | Elimina clave | `error` |
| `Exists(ctx, key)` | Verifica existencia | `(bool, error)` |
| `GetMulti(ctx, keys)` | Obtiene múltiples | `(map[string][]byte, error)` |
| `SetMulti(ctx, values, ttl)` | Almacena múltiples | `error` |
| `DeleteMulti(ctx, keys)` | Elimina múltiples | `(count, error)` |
| `DeleteByPrefix(ctx, prefix)` | Elimina por prefijo | `(count, error)` |
| `GetAndDelete(ctx, key)` | Obtiene y elimina (atómico) | `([]byte, bool, error)` |
| `SetNX(ctx, key, value, ttl)` | Set if Not eXists | `(bool, error)` |
| `Ping(ctx)` | Verifica conexión | `error` |
| `Stats(ctx)` | Estadísticas | `(*CacheStats, error)` |
| `Close()` | Cierra conexión | `error` |

---

## Implementaciones Disponibles

| Adapter | Ubicación | Repositorios Soportados |
|---------|-----------|-------------------------|
| `fs` | `store/v2/adapters/fs/` | Tenant, Client, Scope, Key |
| `pg` | `store/v1/pg/` | User, Token, Consent, MFA, RBAC, Identity, EmailToken, Schema |
| `noop` | (futuro) | Todos (retorna ErrNotImplemented) |

---

## Uso Típico

```go
// 1. Abrir adapter
conn, err := storev2.OpenAdapter(ctx, storev2.AdapterConfig{
    Name:   "fs",
    FSRoot: "/data/hellojohn",
})

// 2. Obtener repositorios
tenants := conn.Tenants()
clients := conn.Clients()
keys := conn.Keys()

// 3. Usar repositorios
tenant, err := tenants.GetBySlug(ctx, "acme")
client, err := clients.Get(ctx, tenant.ID, "my-spa")
jwks, err := keys.GetJWKS(ctx, tenant.ID)
```
