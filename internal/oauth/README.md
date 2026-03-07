# OAuth Providers Implementation

> Implementaciones de bajo nivel de protocolos OAuth2/OIDC para proveedores sociales.

## Propósito

Este paquete contiene clientes HTTP específicos para interactuar con las APIs de identidad de proveedores externos (Google, GitHub, Facebook, etc.).
A diferencia de `internal/http/providers` (que define la interfaz genérica `Provider` para el sistema), este paquete implementa la "fontanería" del protocolo:
-   Construcción de URLs de autorización.
-   Intercambio de códigos por tokens.
-   Validación de ID Tokens (OIDC).
-   Obtención de perfiles de usuario.

## Estructura

```
internal/oauth/
├── google/     # Cliente OIDC para Google
├── github/     # Cliente OAuth2 para GitHub
└── facebook.go # (Pendiente)
```

## Uso

Es consumido principalmente por `internal/http/services/social` para ejecutar los flujos de login.

```go
// Ejemplo de uso en services/social
import "github.com/dropDatabas3/hellojohn/internal/oauth/google"

g := google.New(clientID, clientSecret, redirectURL, scopes)
url, _ := g.AuthURL(ctx, state, nonce)
// ...
token, _ := g.ExchangeCode(ctx, code)
claims, _ := g.VerifyIDToken(ctx, token.IDToken, nonce)
```

## Notas de Diseño

-   **Sin Dependencia de `golang.org/x/oauth2`**: Se ha optado por una implementación ligera y controlada de los flujos, reduciendo dependencias externas.
-   **Discovery Automatico**: El paquete `google` implementa OIDC Discovery para obtener endpoints y claves de firma (JWKS) automáticamente.
