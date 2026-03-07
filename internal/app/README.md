# App - Application Wiring

> Compositor central que conecta Services, Controllers y Router para formar la aplicación HTTP

## Propósito

Este módulo es el **punto de ensamblaje** de la arquitectura en capas de HelloJohn. Recibe las dependencias de infraestructura (DAL, Issuer, Email, etc.) y construye la aplicación completa mediante:

1. **Creación de Services**: Lógica de negocio por dominio
2. **Creación de Controllers**: Handlers HTTP por dominio
3. **Registro de Rutas**: Conexión de endpoints a controllers
4. **Middlewares Globales**: CORS, seguridad, etc.

**Patrón**: Dependency Injection via Composition Root

## Estructura

```
internal/app/
└── app.go      # Única fuente (178 líneas)
    ├── Config       # Configuración (vacía por ahora)
    ├── Deps         # Dependencias requeridas
    ├── App          # Struct con http.Handler
    ├── New()        # Constructor principal
    ├── applyGlobalMiddlewares()  # CORS y otros
    └── getCORSOrigins()          # Helper para CORS
```

## Componentes Principales

| Componente | Tipo | Descripción |
|------------|------|-------------|
| `Config` | struct | Configuración de la app (extensible) |
| `Deps` | struct | Dependencias requeridas para construir la app |
| `App` | struct | Aplicación construida con su `http.Handler` |
| `New()` | función | Constructor principal - wiring completo |

## Dependencias Requeridas (Deps)

| Campo | Tipo | Descripción |
|-------|------|-------------|
| `DAL` | `store.DataAccessLayer` | Acceso a datos |
| `ControlPlane` | `cp.Service` | Gestión de tenants/clients |
| `Email` | `emailv2.Service` | Servicio de email |
| `Issuer` | `*jwtx.Issuer` | Emisor de tokens JWT |
| `JWKSCache` | `*jwtx.JWKSCache` | Cache de JWKS |
| `BaseIssuer` | `string` | URL base del issuer |
| `RefreshTTL` | `time.Duration` | TTL de refresh tokens |
| `SocialCache` | `socialsvc.CacheWriter` | Cache para social login |
| `MasterKey` | `string` | Clave maestra de cifrado |
| `RateLimiter` | `mw.RateLimiter` | Limitador de rate |
| `Social` | `socialsvc.Services` | Servicios de social login |
| `AutoLogin` | `bool` | Auto-login tras registro |
| `FSAdminEnabled` | `bool` | Permitir admin desde FS |
| `OAuthCache` | `oauth.CacheClient` | Cache para OAuth |
| `OAuthCookieName` | `string` | Nombre de cookie OAuth |
| `OAuthAllowBearer` | `bool` | Permitir Bearer tokens |

## Flujo de Construcción

```
New(cfg, deps)
    │
    ├── 1. services.New(deps)
    │       └── Crea aggregator de todos los services
    │
    ├── 2. *ctrl.NewControllers(svcs.*)
    │       ├── authControllers
    │       ├── adminControllers
    │       ├── oidcControllers
    │       ├── oauthControllers
    │       ├── socialControllers
    │       ├── sessionControllers
    │       ├── emailControllers
    │       ├── securityControllers
    │       └── healthControllers
    │
    ├── 3. router.RegisterV2Routes(...)
    │       └── Conecta HTTP mux con controllers
    │
    └── 4. applyGlobalMiddlewares(mux)
            └── CORS, etc.
```

## Dependencias

### Internas
- `internal/controlplane` → Control Plane service
- `internal/email` → Email service
- `internal/http/controllers/*` → Todos los controllers
- `internal/http/middlewares` → Middlewares
- `internal/http/router` → Registro de rutas
- `internal/http/services` → Aggregator de services
- `internal/jwt` → Issuer y JWKS
- `internal/store` → DAL

### Externas
- Ninguna directa (solo stdlib `net/http`, `os`, `strings`, `time`)

## Configuración

| Variable | Descripción | Default |
|----------|-------------|---------|
| `CORS_ALLOWED_ORIGINS` | Origins permitidos (CSV) | `http://localhost:3000,http://localhost:3001` |

## Ejemplo de Uso

```go
// En internal/http/server/wiring.go
app, err := appv2.New(appv2.Config{}, appv2.Deps{
    DAL:          dal,
    ControlPlane: cpService,
    Email:        emailService,
    Issuer:       issuer,
    // ... resto de deps
})
if err != nil {
    return nil, err
}

// app.Handler es el http.Handler completo
srv := &http.Server{
    Handler: app.Handler,
}
```

## Ver También

- [internal/http/server](../http/server/README.md) - Quién construye las Deps
- [internal/http/services](../http/services/README.md) - Services aggregator
- [internal/http/controllers](../http/controllers/README.md) - Controllers
- [internal/http/router](../http/router/README.md) - Registro de rutas
