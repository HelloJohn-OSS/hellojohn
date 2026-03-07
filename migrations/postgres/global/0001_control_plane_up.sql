-- migrations/postgres/global/0001_control_plane_up.sql
-- Control Plane Schema: 6 tablas para Global DB (EPIC 008)
-- Estas tablas son la fuente de verdad en modos ModeFSGlobalDB y ModeFullDB.
-- NO mezclar con las Tenant DBs (que tienen app_user, rbac_role, etc.)

CREATE TABLE IF NOT EXISTS cp_tenant (
    id          UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    slug        TEXT        UNIQUE NOT NULL,
    name        TEXT        NOT NULL,
    language    TEXT        NOT NULL DEFAULT 'en',
    settings    JSONB       NOT NULL DEFAULT '{}',
    enabled     BOOLEAN     NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cp_client (
    id             UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id      UUID        NOT NULL REFERENCES cp_tenant(id) ON DELETE CASCADE,
    client_id      TEXT        NOT NULL,
    name           TEXT        NOT NULL,
    type           TEXT        NOT NULL DEFAULT 'public',
    secret_enc     TEXT,
    settings       JSONB       NOT NULL DEFAULT '{}',
    redirect_uris  TEXT[]      NOT NULL DEFAULT '{}',
    allowed_scopes TEXT[]      NOT NULL DEFAULT '{}',
    enabled        BOOLEAN     NOT NULL DEFAULT true,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, client_id)
);

CREATE TABLE IF NOT EXISTS cp_scope (
    id          UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id   UUID        NOT NULL REFERENCES cp_tenant(id) ON DELETE CASCADE,
    name        TEXT        NOT NULL,
    description TEXT        NOT NULL DEFAULT '',
    claims      TEXT[]      NOT NULL DEFAULT '{}',
    system      BOOLEAN     NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS cp_claims_config (
    id             UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    tenant_id      UUID        NOT NULL REFERENCES cp_tenant(id) ON DELETE CASCADE,
    claim_name     TEXT        NOT NULL,
    description    TEXT        NOT NULL DEFAULT '',
    source_type    TEXT        NOT NULL DEFAULT 'static',
    config         JSONB       NOT NULL DEFAULT '{}',
    scopes         TEXT[]      NOT NULL DEFAULT '{}',
    always_include BOOLEAN     NOT NULL DEFAULT false,
    required       BOOLEAN     NOT NULL DEFAULT false,
    enabled        BOOLEAN     NOT NULL DEFAULT true,
    system         BOOLEAN     NOT NULL DEFAULT false,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, claim_name)
);

-- cp_admin NO tiene FK a cp_tenant: los admins son cross-tenant (globales).
-- tenant_ids almacena los UUIDs de los tenants a los que tiene acceso.
CREATE TABLE IF NOT EXISTS cp_admin (
    id              UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    email           TEXT        UNIQUE NOT NULL,
    password_hash   TEXT        NOT NULL,
    name            TEXT        NOT NULL DEFAULT '',
    role            TEXT        NOT NULL DEFAULT 'admin',
    tenant_ids      TEXT[]      NOT NULL DEFAULT '{}',
    enabled         BOOLEAN     NOT NULL DEFAULT true,
    last_seen_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cp_admin_refresh_token (
    id          UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    admin_id    UUID        NOT NULL REFERENCES cp_admin(id) ON DELETE CASCADE,
    token_hash  TEXT        UNIQUE NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Índices de soporte para consultas frecuentes
CREATE INDEX IF NOT EXISTS idx_cp_client_tenant            ON cp_client(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cp_scope_tenant             ON cp_scope(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cp_claims_config_tenant     ON cp_claims_config(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cp_admin_refresh_token_admin ON cp_admin_refresh_token(admin_id);
CREATE INDEX IF NOT EXISTS idx_cp_admin_refresh_token_hash  ON cp_admin_refresh_token(token_hash);
