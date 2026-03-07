# Bootstrap - Admin User Setup

> Creación interactiva del primer usuario administrador del sistema

## Propósito

Este módulo maneja la creación del primer administrador global cuando HelloJohn se inicia por primera vez. Detecta si existen administradores en el sistema y, si no hay ninguno, guía al usuario a través de un proceso interactivo para crear uno.

**Contexto**: Los administradores globales acceden al sistema sin requerir un tenant específico.

## Estructura

```
internal/bootstrap/
└── admin.go    # Única fuente (208 líneas)
    ├── AdminBootstrapConfig   # Configuración
    ├── CheckAndCreateAdmin()  # Entry point principal
    ├── ShouldRunBootstrap()   # Check si ejecutar
    ├── hasExistingAdmin()     # Verificación
    ├── createAdminUser()      # Creación
    └── promptAdminCredentials() # Input interactivo
```

## Funciones Públicas

| Función | Descripción |
|---------|-------------|
| `ShouldRunBootstrap(ctx, dal)` | Retorna `true` si no hay admins |
| `CheckAndCreateAdmin(ctx, cfg)` | Flujo completo de bootstrap |

## Configuración

```go
type AdminBootstrapConfig struct {
    DAL           store.DataAccessLayer
    SkipPrompt    bool   // Para testing (no-interactivo)
    AdminEmail    string // Pre-rellenado (opcional)
    AdminPassword string // Pre-rellenado (opcional)
}
```

## Flujo de Ejecución

```
ShouldRunBootstrap()
    │
    └── ¿Existen admins? ─── Sí → return false
            │
            No
            │
            └── return true
                    │
                    ▼
        CheckAndCreateAdmin()
                    │
            ┌───────┴───────┐
         Interactivo?    SkipPrompt?
            │                 │
    promptAdminCredentials()  usar cfg.Email/Password
            │                 │
            └───────┬─────────┘
                    │
            createAdminUser()
                    │
            Hash password (argon2id)
                    │
            adminRepo.Create()
```

## Dependencias

### Internas
- `internal/domain/repository` → `AdminFilter`, `CreateAdminInput`, `IsNotFound`
- `internal/security/password` → `Hash()` (argon2id)
- `internal/store` → `DataAccessLayer`

### Externas
- `golang.org/x/term` → Input de password oculto

## Seguridad

| Aspecto | Implementación |
|---------|----------------|
| Password hashing | Argon2id (via `security/password`) |
| Mínimo password | 10 caracteres |
| Input oculto | `term.ReadPassword()` |
| Confirmación | Requiere escribir password 2 veces |

## Ejemplo de Uso

```go
// En cmd/service/main.go
if bootstrap.ShouldRunBootstrap(ctx, dal) {
    err := bootstrap.CheckAndCreateAdmin(ctx, bootstrap.AdminBootstrapConfig{
        DAL: dal,
    })
    if err != nil {
        log.Printf("Bootstrap failed: %v", err)
    }
}
```

### Modo No-Interactivo (Testing)

```go
err := bootstrap.CheckAndCreateAdmin(ctx, bootstrap.AdminBootstrapConfig{
    DAL:           dal,
    SkipPrompt:    true,
    AdminEmail:    "admin@test.com",
    AdminPassword: "supersecret123",
})
```

## Ver También

- [cmd/service](../../cmd/service/README.md) - Quién llama al bootstrap
- [internal/store](../store/README.md) - DAL y ConfigAccess
