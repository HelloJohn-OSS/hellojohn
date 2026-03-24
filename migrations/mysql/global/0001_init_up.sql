-- Consolidated Control Plane Schema for MySQL 8.0+ (Global DB)

-- ─── 1. Tenants ───
CREATE TABLE IF NOT EXISTS cp_tenant (
    id         CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    slug       VARCHAR(255) UNIQUE NOT NULL,
    name       VARCHAR(255) NOT NULL,
    language   VARCHAR(10)  NOT NULL DEFAULT 'en',
    settings   JSON         NOT NULL,
    enabled    TINYINT(1)   NOT NULL DEFAULT 1,
    created_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── 2. Clients ───
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── 3. Scopes ───
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── 4. Claims Config ───
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── 5. Admins (cross-tenant, no FK to cp_tenant) ───
CREATE TABLE IF NOT EXISTS cp_admin (
    id                    CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    email                 VARCHAR(255) UNIQUE NOT NULL,
    password_hash         TEXT         NOT NULL,
    name                  VARCHAR(255) NOT NULL DEFAULT '',
    role                  VARCHAR(50)  NOT NULL DEFAULT 'admin',
    tenant_ids            JSON         NOT NULL,
    enabled               TINYINT(1)   NOT NULL DEFAULT 1,
    status                VARCHAR(50)  NOT NULL DEFAULT 'active',
    disabled_at           DATETIME(6),
    onboarding_completed  TINYINT(1)   NOT NULL DEFAULT 0,
    invite_token_hash     VARCHAR(255),
    invite_expires_at     DATETIME(6),
    created_by            CHAR(36),
    email_verified        TINYINT(1)   NOT NULL DEFAULT 0,
    social_provider       VARCHAR(100) NOT NULL DEFAULT '',
    plan                  VARCHAR(50)  NOT NULL DEFAULT 'free',
    last_seen_at          DATETIME(6),
    created_at            DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at            DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── 6. Admin Refresh Tokens ───
CREATE TABLE IF NOT EXISTS cp_admin_refresh_token (
    id         CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    admin_id   CHAR(36)     NOT NULL,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    expires_at DATETIME(6)  NOT NULL,
    created_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_cp_admin_token FOREIGN KEY (admin_id) REFERENCES cp_admin(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── 7. System Settings ───
CREATE TABLE IF NOT EXISTS system_settings (
    `key`        VARCHAR(128) NOT NULL PRIMARY KEY,
    `value`      JSON         NOT NULL,
    `updated_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    `updated_by` VARCHAR(255) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ─── Indexes ───
CREATE INDEX idx_cp_client_tenant     ON cp_client(tenant_id);
CREATE INDEX idx_cp_scope_tenant      ON cp_scope(tenant_id);
CREATE INDEX idx_cp_claims_tenant     ON cp_claims_config(tenant_id);
CREATE INDEX idx_cp_admin_token_admin ON cp_admin_refresh_token(admin_id);
CREATE INDEX idx_cp_admin_token_hash  ON cp_admin_refresh_token(token_hash);
CREATE UNIQUE INDEX idx_cp_admin_invite_token ON cp_admin(invite_token_hash);
