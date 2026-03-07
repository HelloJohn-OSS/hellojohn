# Store Adapters

> Implementaciones concretas de los repositorios del Data Access Layer.

## Arquitectura

El paquete `adapters` contiene los drivers específicos para diferentes tecnologías de almacenamiento. Cada adapter debe implementar la interfaz `store.Adapter` y registrarse mediante `store.RegisterAdapter` en su función `init()`.

## Adapters Disponibles

### 1. `fs` (FileSystem) - Control Plane

Implementación basada en archivos YAML y JSON. Es el backend exclusivo para el **Control Plane** (Tenants, Clients, Scopes, Keys).

-   **Ruta Data**: `data/hellojohn/` (configurable).
-   **Concurrency**: Thread-safe usando `sync.RWMutex`.
-   **Formatos**:
    -   `tenants/{slug}/tenant.yaml`
    -   `tenants/{slug}/clients.yaml`
    -   `keys/active.json`

### 2. `pg` (PostgreSQL) - Data Plane

Implementación de alto rendimiento para el **Data Plane** (User data).

-   **Pool**: Usa `pgxpool` para gestión eficiente de conexiones.
-   **Dynamic User Fields**: Construye queries SQL dinámicas para soportar campos personalizados en la tabla `app_user` sin usar JSONB para columnas indexables de alto rendimiento.
-   **Separación**: Cada tenant tiene su propia base de datos aislada (o schema, según config DSN).

### 3. `mysql` (MySQL 8.0+) - Data Plane

Alternativa a PostgreSQL.

-   **Soporte JSON**: Usa columnas nativas JSON para estructuras complejas.
-   **Driver**: `go-sql-driver/mysql`.

### 4. `noop` (No Operation)

Adapter para testing que retorna `ErrNotImplemented` o valores vacíos. Útil para tests unitarios que necesitan un mock rápido del store.

## Auto-Registro (`dal`)

El paquete `internal/store/adapters/dal` facilita la importación de todos los drivers necesarios en el binario final.

```go
import _ "github.com/dropDatabas3/hellojohn/internal/store/adapters/dal"
```

Esto ejecuta los `init()` de `fs`, `pg` y `mysql`, registrándolos en el `store.Factory` global.
