# ControlPlane V2 — Arquitectura

## Resumen

ControlPlane V2 es la **capa de servicio** para operaciones del Control Plane (configuración de tenants, clients, scopes). Usa Store V2 como backend de persistencia.

## Flujo de Datos

```
┌─────────────────────────────────────────────────────────────────┐
│                         HANDLERS                                │
│  AdminHandler.CreateClient(w, r)                                │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                   CONTROLPLANE SERVICE                          │
│  cp := controlplane.NewService(storeMgr)                        │
│  cp.CreateClient(ctx, slug, input)                              │
│    1. Validar ClientID, RedirectURIs                            │
│    2. Cifrar Secret (confidential clients)                      │
│    3. Delegar a Store V2                                        │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                       STORE V2                                  │
│  store.ConfigAccess().Clients(slug).Create(...)                 │
│    → Escribe clients.yaml (FS adapter)                          │
└─────────────────────────────────────────────────────────────────┘
```

## Interface del Servicio

```go
type Service interface {
    // Tenants
    ListTenants(ctx) ([]Tenant, error)
    GetTenant(ctx, slug) (*Tenant, error)
    CreateTenant(ctx, name, slug, language) (*Tenant, error)
    UpdateTenantSettings(ctx, slug, settings) error
    DeleteTenant(ctx, slug) error

    // Clients
    ListClients(ctx, slug) ([]Client, error)
    GetClient(ctx, slug, clientID) (*Client, error)
    CreateClient(ctx, slug, input) (*Client, error)
    UpdateClient(ctx, slug, input) (*Client, error)
    DeleteClient(ctx, slug, clientID) error
    DecryptClientSecret(ctx, slug, clientID) (string, error)

    // Scopes
    ListScopes(ctx, slug) ([]Scope, error)
    CreateScope(ctx, slug, name, desc) (*Scope, error)
    DeleteScope(ctx, slug, name) error

    // Validations
    ValidateClientID(id) bool
    ValidateRedirectURI(uri) bool
    IsScopeAllowed(client, scope) bool
}
```

## Uso en Handlers

```go
// main.go
storeMgr, _ := store.NewManager(ctx, store.ManagerConfig{...})
cpService := controlplane.NewService(storeMgr)

// handler
func (h *AdminHandler) CreateClient(w, r) {
    input := controlplane.ClientInput{...}
    client, err := h.cp.CreateClient(r.Context(), slug, input)
    // ...
}


o


// En handler
client, err := cpService.CreateClient(ctx, slug, controlplane.ClientInput{
    Name:         "My App",
    ClientID:     "my-app",
    Type:         "public",
    RedirectURIs: []string{"https://myapp.com/callback"},
})

```



## Responsabilidades

| Componente | Responsabilidad |
|------------|-----------------|
| **ControlPlane Service** | Validaciones, cifrado, orquestación |
| **Store V2** | CRUD puro, multi-driver |
| **Handlers** | HTTP, parsing, response |

## Cifrado Automático

El servicio cifra automáticamente:
- `TenantSettings.SMTP.Password` → `PasswordEnc`
- `TenantSettings.UserDB.DSN` → `DSNEnc`
- `TenantSettings.Cache.Password` → `PassEnc`
- `ClientInput.Secret` → `SecretEnc`

Los campos plain se limpian antes de persistir.

## Migración desde V1

| Antes (V1) | Después (V2) |
|------------|--------------|
| `controlplane.ControlPlane` interface | `controlplane.Service` interface |
| `controlplane/fs.FSProvider` | `store.ConfigAccess()` → FS adapter |
| Acceso directo a YAML | Store V2 abstrae persistencia |
| Cifrado en FSProvider | Cifrado en Service |
