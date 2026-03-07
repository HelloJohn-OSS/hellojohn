# Migrations

> Scripts de gestión de esquema para las bases de datos de HelloJohn.

## Estructura

```
migrations/
├── postgres/
│   ├── tenant/           # Migraciones para bases de datos de Tenant (Aisladas)
│   │   ├── 0001_init_up.sql
│   │   ├── ...
│   │   └── embed.go      # Embed FS para uso en la aplicación
│   │
│   └── 0001_init_up.sql  # (Legacy/Shared) Migraciones para modo Global DB
├── mysql/                # Soporte parcial MySQL
└── mongo/                # Soporte parcial MongoDB
```

## Modo: Database per Tenant (Principal)

La aplicación V2 opera principalmente en modo aislamiento, donde cada Tenant tiene su propia base de datos (o schema).
Las migraciones relevantes se encuentran en `postgres/tenant/`.

### Características del Esquema Tenant
-   **Sin colisiones**: No existe columna `tenant_id` en la mayoría de las tablas (`app_user`, `refresh_token`), ya que el aislamiento es físico.
-   **Tablas Principales**: `app_user`, `identity`, `refresh_token`, `rbac_role`, `user_consent`.
-   **Compatibilidad**: Los scripts incluyen comprobaciones `IF NOT EXISTS` y columnas de compatibilidad para evitar romper bases de datos pre-existentes importadas.

## Ejecución

Las migraciones se ejecutan automáticamente al iniciar la conexión con el Data Access Layer de un tenant (ver `internal/store/factory.go` y `internal/store/adapters/pg`).
El sistema utiliza una tabla `schema_migrations` interna para rastrear versiones aplicadas.

## Referencia de Versiones (Postgres Tenant)

-   `0001_init`: Esquema base consolidado (Users, Identities, Tokens, RBAC, MFA).
-   `0002_add_user_language`: Agrega campo `language` a `app_user`.
-   `0003_create_sessions`: Crea tabla `session` para gestión de sesiones centralizadas.
-   `0004_rbac_schema_fix`: Ajustes menores en tablas RBAC.
