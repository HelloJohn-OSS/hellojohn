# Claims - Custom Claims Processing

> 🚧 **MÓDULO EN DESARROLLO** - La mayoría de archivos son stubs

## Propósito

Este módulo está diseñado para manejar claims personalizados en tokens JWT:

- **Namespaces**: Generar namespaces OIDC-compliant para claims custom
- **Resolver**: Resolver claims dinámicos desde diferentes fuentes (webhook, static, expressions)
- **CEL Engine**: Evaluar expresiones CEL para claims condicionales
- **JSON Schema**: Validar claims contra schemas

## Estado Actual

| Archivo | Estado | Descripción |
|---------|--------|-------------|
| `namespaces.go` | ✅ Implementado | `SystemNamespace(issuer)` - genera namespace |
| `cel_engine.go` | ❌ Stub | Solo `package claims` |
| `jsonschema.go` | ❌ Stub | Solo `package claims` |
| `resolver/*.go` | ❌ Stubs | 5 archivos vacíos |

## Funciones Implementadas

```go
// Construye namespace de claims del sistema
// Ej: "https://issuer.example.com/claims/sys"
func SystemNamespace(issuer string) string
```

### Uso

```go
issuer := "https://auth.myapp.com"
ns := claims.SystemNamespace(issuer)
// ns = "https://auth.myapp.com/claims/sys"
```

## Dependencias

### Consumidores
- `internal/http/middlewares/rbac.go` - RBAC middleware
- `internal/http/middlewares/admin.go` - Admin auth
- `internal/http/helpers/sysclaims.go` - Claims helpers

### Externas
- Ninguna

## Roadmap (Stubs)

1. **CEL Engine**: Expresiones condicionales para claims
2. **JSON Schema**: Validación de claims custom
3. **Resolver Providers**:
   - `static.go` - Claims estáticos por configuración
   - `webhook.go` - Claims desde webhooks externos
   - `expr.go` - Claims calculados con expresiones

## Ver También

- [internal/jwt](../jwt/README.md) - Emisión de tokens con claims
