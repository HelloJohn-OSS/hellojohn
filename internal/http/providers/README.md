# HTTP Providers

> Sistema de plugins para autenticación con proveedores externos (Social Login / Enterprise SSO).

## Propósito

Este paquete define la interfaz unificada `Provider` y el registro dinámico para cargar estrategias de autenticación en tiempo de ejecución según la configuración del tenant.

## Arquitectura

-   **Interfaz `Provider`**: Contrato común para todos los proveedores (Authorize, Exchange, UserInfo).
-   **Registry**: Factory que instancia proveedores bajo demanda y los cachea por tenant.
-   **Configuración**: `ProviderConfig` normaliza las credenciales y scopes.

## Estructura

```
internal/http/providers/
├── provider.go       # Interfaz Provider y struct UserProfile
├── registry.go       # Singleton Registry con caching
├── google/           # Implementación Google OIDC
├── github/           # Implementación GitHub OAuth2
└── ...
```

## Estado de Implementación

Actualmente, el sistema base (`registry.go`, `provider.go`) está implementado, pero los proveedores individuales (Google, GitHub, etc.) son **skeletons (placeholders)** pendientes de implementación de la lógica real de OAuth2/OIDC.

## Uso (Futuro)

```go
// 1. Obtener proveedor desde registry
prov, err := registry.GetProvider(ctx, "tenant-slug", "google", config)

// 2. Generar URL de autorización
url := prov.AuthorizeURL(state, nonce, scopes)

// 3. Intercambiar código por tokens
tokens, err := prov.Exchange(ctx, code)

// 4. Obtener perfil de usuario
profile, err := prov.UserInfo(ctx, tokens.AccessToken)
```
