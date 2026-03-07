# Entry Point - cmd/service

> Punto de entrada principal de la aplicación HelloJohn

## Propósito

Este módulo contiene el `main.go` que:

1. Carga configuración desde `.env` o variables de entorno
2. Inicializa el servidor HTTP con todas las dependencias (DAL, Services, Controllers)
3. Ejecuta el bootstrap de administrador si no existen usuarios admin
4. Inicia el servidor HTTP en el puerto configurado

## Estructura

```
cmd/
└── service/
    └── main.go      # Entry point único (72 líneas)
```

## Flujo de Inicialización

```
main()
  │
  ├── 1. godotenv.Load()           # Cargar .env
  │
  ├── 2. BuildV2HandlerWithDeps()  # Wiring de dependencias
  │      └── Returns: handler, cleanup, DAL
  │
  ├── 3. ShouldRunBootstrap()      # ¿Hay admins?
  │      └── Si no hay → promptAdminCredentials()
  │
  └── 4. http.Server.ListenAndServe()
```

## Dependencias

### Internas
- `internal/bootstrap` → Creación interactiva de primer admin
- `internal/http/server` → `BuildV2HandlerWithDeps()` (wiring)
- `internal/store/adapters/dal` → Auto-registro de adapters (fs, pg, mysql)

### Externas
- `github.com/joho/godotenv` → Carga de archivos `.env`

## Configuración

| Variable | Descripción | Default |
|----------|-------------|---------|
| `V2_SERVER_ADDR` | Dirección del servidor HTTP | `:8080` |
| `SIGNING_MASTER_KEY` | Clave maestra para JWT (hex, 64 chars) | **Requerido** |
| `SECRETBOX_MASTER_KEY` | Clave de cifrado (base64, 32 bytes) | **Requerido** |
| `FS_ROOT` | Directorio raíz del Control Plane | `data` |

Ver variables adicionales en `internal/http/server/wiring.go`.

## Timeouts del Servidor

| Timeout | Valor |
|---------|-------|
| ReadTimeout | 10s |
| WriteTimeout | 30s |

## Ejecución

```bash
# Con .env
go run ./cmd/service

# Con variables explícitas
FS_ROOT=./data/hellojohn \
SIGNING_MASTER_KEY=<64-hex-chars> \
SECRETBOX_MASTER_KEY=<base64-key> \
go run ./cmd/service
```

## Ver También

- [internal/http/server](../../internal/http/server/README.md) - Wiring de dependencias
- [internal/bootstrap](../../internal/bootstrap/README.md) - Bootstrap de admin
- [internal/store](../../internal/store/README.md) - Data Access Layer
