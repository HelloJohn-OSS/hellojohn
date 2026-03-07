-- migrations/mysql/global/0001_control_plane_up.sql
-- Control Plane Schema para MySQL 8.0+ (EPIC 008)
-- Equivalente lógico del DDL PostgreSQL con adaptaciones de dialecto:
--   UUID          → CHAR(36) DEFAULT (UUID())   [paréntesis requerido en MySQL 8.0+]
--   TIMESTAMPTZ   → DATETIME(6)
--   JSONB / TEXT  → JSON
--   TEXT[]        → JSON                         [arrays como JSON array]
--   BOOLEAN       → TINYINT(1)
--   DEFAULT now() → DEFAULT CURRENT_TIMESTAMP(6)

CREATE TABLE IF NOT EXISTS cp_tenant (
    id          CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    slug        VARCHAR(255) UNIQUE NOT NULL,
    name        VARCHAR(255) NOT NULL,
    language    VARCHAR(10)  NOT NULL DEFAULT 'en',
    settings    JSON         NOT NULL,
    enabled     TINYINT(1)   NOT NULL DEFAULT 1,
    created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
);

CREATE TABLE IF NOT EXISTS cp_client (
    id             CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    tenant_id      CHAR(36)     NOT NULL,
    client_id      VARCHAR(255) NOT NULL,
    name           VARCHAR(255) NOT NULL,
    type           VARCHAR(50)  NOT NULL DEFAULT 'public',
    secret_enc     TEXT,
    settings       JSON         NOT NULL,
    redirect_uris  JSON         NOT NULL,
    allowed_scopes JSON         NOT NULL,
    enabled        TINYINT(1)   NOT NULL DEFAULT 1,
    created_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_cp_client_tenant FOREIGN KEY (tenant_id) REFERENCES cp_tenant(id) ON DELETE CASCADE,
    UNIQUE KEY uq_cp_client (tenant_id, client_id)
);

CREATE TABLE IF NOT EXISTS cp_scope (
    id          CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    tenant_id   CHAR(36)     NOT NULL,
    name        VARCHAR(255) NOT NULL,
    description TEXT         NOT NULL DEFAULT '',
    claims      JSON         NOT NULL,
    system      TINYINT(1)   NOT NULL DEFAULT 0,
    created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_cp_scope_tenant FOREIGN KEY (tenant_id) REFERENCES cp_tenant(id) ON DELETE CASCADE,
    UNIQUE KEY uq_cp_scope (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS cp_claims_config (
    id             CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    tenant_id      CHAR(36)     NOT NULL,
    claim_name     VARCHAR(255) NOT NULL,
    description    TEXT         NOT NULL DEFAULT '',
    source_type    VARCHAR(50)  NOT NULL DEFAULT 'static',
    config         JSON         NOT NULL,
    scopes         JSON         NOT NULL,
    always_include TINYINT(1)   NOT NULL DEFAULT 0,
    required       TINYINT(1)   NOT NULL DEFAULT 0,
    enabled        TINYINT(1)   NOT NULL DEFAULT 1,
    system         TINYINT(1)   NOT NULL DEFAULT 0,
    created_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_cp_claims_tenant FOREIGN KEY (tenant_id) REFERENCES cp_tenant(id) ON DELETE CASCADE,
    UNIQUE KEY uq_cp_claims_config (tenant_id, claim_name)
);

-- cp_admin: cross-tenant, sin FK a cp_tenant.
-- tenant_ids almacena JSON array de UUIDs de tenants con acceso.
CREATE TABLE IF NOT EXISTS cp_admin (
    id            CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    email         VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT         NOT NULL,
    name          VARCHAR(255) NOT NULL DEFAULT '',
    role          VARCHAR(50)  NOT NULL DEFAULT 'admin',
    tenant_ids    JSON         NOT NULL,
    enabled       TINYINT(1)   NOT NULL DEFAULT 1,
    last_seen_at  DATETIME(6),
    created_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
);

CREATE TABLE IF NOT EXISTS cp_admin_refresh_token (
    id          CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    admin_id    CHAR(36)     NOT NULL,
    token_hash  VARCHAR(255) UNIQUE NOT NULL,
    expires_at  DATETIME(6)  NOT NULL,
    created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_cp_admin_token FOREIGN KEY (admin_id) REFERENCES cp_admin(id) ON DELETE CASCADE
);

CREATE INDEX idx_cp_client_tenant      ON cp_client(tenant_id);
CREATE INDEX idx_cp_scope_tenant       ON cp_scope(tenant_id);
CREATE INDEX idx_cp_claims_tenant      ON cp_claims_config(tenant_id);
CREATE INDEX idx_cp_admin_token_admin  ON cp_admin_refresh_token(admin_id);
