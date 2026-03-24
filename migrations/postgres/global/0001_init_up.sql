-- Consolidated Control Plane Schema (Global DB)
-- These tables are the source of truth in ModeFSGlobalDB and ModeFullDB.
-- DO NOT mix with Tenant DBs (which have app_user, rbac_role, etc.)

-- ─── 1. Tenants ───
CREATE TABLE IF NOT EXISTS cp_tenant (
    id         UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    slug       TEXT        UNIQUE NOT NULL,
    name       TEXT        NOT NULL,
    language   TEXT        NOT NULL DEFAULT 'en',
    settings   JSONB       NOT NULL DEFAULT '{}',
    enabled    BOOLEAN     NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ─── 2. Clients ───
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

-- ─── 3. Scopes ───
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

-- ─── 4. Claims Config ───
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

-- ─── 5. Admins (cross-tenant, no FK to cp_tenant) ───
CREATE TABLE IF NOT EXISTS cp_admin (
    id                    UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    email                 TEXT        UNIQUE NOT NULL,
    password_hash         TEXT        NOT NULL,
    name                  TEXT        NOT NULL DEFAULT '',
    role                  TEXT        NOT NULL DEFAULT 'admin',
    tenant_ids            TEXT[]      NOT NULL DEFAULT '{}',
    enabled               BOOLEAN     NOT NULL DEFAULT true,
    status                TEXT        NOT NULL DEFAULT 'active',
    disabled_at           TIMESTAMPTZ,
    onboarding_completed  BOOLEAN     NOT NULL DEFAULT false,
    invite_token_hash     TEXT,
    invite_expires_at     TIMESTAMPTZ,
    created_by            UUID,
    email_verified        BOOLEAN     NOT NULL DEFAULT false,
    social_provider       TEXT        NOT NULL DEFAULT '',
    plan                  TEXT        NOT NULL DEFAULT 'free',
    last_seen_at          TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ─── 6. Admin Refresh Tokens ───
CREATE TABLE IF NOT EXISTS cp_admin_refresh_token (
    id         UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    admin_id   UUID        NOT NULL REFERENCES cp_admin(id) ON DELETE CASCADE,
    token_hash TEXT        UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ─── 7. System Settings ───
CREATE TABLE IF NOT EXISTS system_settings (
    key        TEXT        NOT NULL PRIMARY KEY,
    value      JSONB       NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by TEXT        NOT NULL DEFAULT ''
);

COMMENT ON TABLE system_settings IS 'Global key-value settings for control plane. Key email_provider stores encrypted GlobalEmailProviderSettings.';

-- ─── Indexes ───
CREATE INDEX IF NOT EXISTS idx_cp_client_tenant             ON cp_client(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cp_scope_tenant              ON cp_scope(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cp_claims_config_tenant      ON cp_claims_config(tenant_id);
CREATE INDEX IF NOT EXISTS idx_cp_admin_refresh_token_admin ON cp_admin_refresh_token(admin_id);
CREATE INDEX IF NOT EXISTS idx_cp_admin_refresh_token_hash  ON cp_admin_refresh_token(token_hash);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cp_admin_invite_token ON cp_admin(invite_token_hash)
    WHERE invite_token_hash IS NOT NULL;
