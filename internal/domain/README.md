# Domain Layer

> Definiciones centrales del dominio: Entidades, Interfaces de Repositorio y Reglas de Negocio base.

## Propósito

Este paquete define el **Lenguaje Ubicuo** del sistema. Contiene:
-   **Entidades**: Estructuras de datos puras (`Tenant`, `User`, `Client`).
-   **Interfaces**: Contratos para la persistencia (`TenantRepository`, `UserRepository`).
-   **Errores**: Errores de dominio centinela (`ErrNotFound`, `ErrConflict`).
-   **Value Objects**: Tipos con validación intrínseca (`IssuerMode`).

No contiene implementación de persistencia ni lógica HTTP. Es el núcleo estable de la arquitectura Hexagonal/Clean.

## Estructura

```
internal/domain/
├── repository/      # Interfaces y Modelos
│   ├── tenant.go    # Tenant + Settings (SMTP, Auth, DB)
│   ├── client.go    # Client OIDC + Config
│   ├── user.go      # User + Identity
│   ├── errors.go    # Errores centinela (ErrNotFound, etc)
│   └── doc.go       # Documentación del paquete
└── types/           # Tipos compartidos / Enums
    └── issuer_mode.go # Enums para modo de issuer
```

## Entidades Principales

### Tenant
Agrupa la configuración de un cliente del sistema SaaS.
-   **Settings**: Configuración jerárquica (`SMTP`, `UserDB`, `Cache`, `Security`).
-   **Seguridad**: Campos sensibles tienen doble representación:
    -   `Password` (Plain): Solo en memoria/input, ignorado en YAML (`yaml:"-"`).
    -   `PasswordEnc` (Cifrado): Persistido en YAML/DB.

### Client
Aplicación que consume la identidad (Relying Party).
-   **Tipos**: `public` (SPA/Mobile) vs `confidential` (Backend).
-   **OAuth2**: Configuración detallada de `GrantTypes`, `RedirectURIs`, `TTLs`.

### User
Usuario final de un Tenant.
-   **Identity**: Separación entre Usuario e Identidad (Password, Google, GitHub).
-   **Perfil**: Campos estándar OIDC (`sub`, `name`, `picture`) + `CustomFields`.

## Interfaces de Repositorio

Definen **qué** se puede hacer, no **cómo**. Las implementaciones residen en `internal/store`.

```go
type UserRepository interface {
    GetByEmail(ctx, tenantID, email) (*User, *Identity, error)
    Create(ctx, input) (*User, *Identity, error)
    // ...
}
```

## Errores de Dominio

Uso de errores centinela para manejo agnóstico del storage:

```go
if errors.Is(err, repository.ErrNotFound) {
    // Manejar 404
}
```

## Dependencias

Este paquete **no debe depender de nadie** (salvo stdlib). Es el nivel más bajo en el grafo de dependencias internas.

## Ver También

- [internal/store](../store/README.md) - Implementación de estas interfaces.
- [internal/controlplane](../controlplane/README.md) - Lógica de negocio sobre estas entidades.
