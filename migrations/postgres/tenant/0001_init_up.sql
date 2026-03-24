-- Consolidated Tenant Schema
-- Applied to each tenant's isolated database/schema.
-- This is the complete schema for tenant databases.

BEGIN;

-- ─── 1. Users & Profiles ───
CREATE TABLE IF NOT EXISTS app_user (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email            TEXT        NOT NULL,
    email_verified   BOOLEAN     NOT NULL DEFAULT false,
    name             TEXT,
    given_name       TEXT,
    family_name      TEXT,
    picture          TEXT,
    locale           TEXT,
    language         TEXT        DEFAULT '',
    status           TEXT        NOT NULL DEFAULT 'active',
    profile          JSONB       NOT NULL DEFAULT '{}',
    metadata         JSONB       NOT NULL DEFAULT '{}',
    custom_data      JSONB       NOT NULL DEFAULT '{}'::jsonb,
    source_client_id TEXT,
    disabled_at      TIMESTAMPTZ,
    disabled_reason  TEXT,
    disabled_until   TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (email)
);

-- ─── 2. Identities (Auth Providers) ───
CREATE TABLE IF NOT EXISTS identity (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    provider         TEXT        NOT NULL,
    provider_user_id TEXT,
    email            TEXT,
    email_verified   BOOLEAN,
    password_hash    TEXT,
    data             JSONB       DEFAULT '{}',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_identity_user ON identity(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_identity_provider_uid ON identity(provider, provider_user_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_identity_user_provider ON identity(user_id, provider);

-- ─── 3. Refresh Tokens ───
CREATE TABLE IF NOT EXISTS refresh_token (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    client_id_text TEXT,
    token_hash     TEXT        NOT NULL UNIQUE,
    issued_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,
    rotated_from   UUID        NULL REFERENCES refresh_token(id) ON DELETE SET NULL,
    revoked_at     TIMESTAMPTZ NULL,
    metadata       JSONB       DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_refresh_token_user ON refresh_token(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_token_expires ON refresh_token(expires_at) WHERE revoked_at IS NULL;

-- ─── 4. RBAC (Role Based Access Control) ───
CREATE TABLE IF NOT EXISTS rbac_role (
    id            UUID        DEFAULT gen_random_uuid(),
    name          TEXT        PRIMARY KEY,
    description   TEXT,
    permissions   TEXT[]      NOT NULL DEFAULT '{}',
    inherits_from TEXT,
    system        BOOLEAN     NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rbac_user_role (
    user_id     UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    role_name   TEXT        NOT NULL REFERENCES rbac_role(name) ON DELETE CASCADE,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_name)
);

-- ─── 5. Email Verification Tokens ───
CREATE TABLE IF NOT EXISTS email_verification_token (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    token_hash BYTEA       NOT NULL UNIQUE,
    sent_to    TEXT        NOT NULL,
    ip         INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_email_verif_token_expires_at ON email_verification_token(expires_at);
CREATE INDEX IF NOT EXISTS idx_email_verif_token_user ON email_verification_token(user_id);

-- ─── 6. Password Reset Tokens ───
CREATE TABLE IF NOT EXISTS password_reset_token (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    token_hash BYTEA       NOT NULL UNIQUE,
    sent_to    TEXT        NOT NULL,
    ip         INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_pwd_reset_token_expires_at ON password_reset_token(expires_at);
CREATE INDEX IF NOT EXISTS idx_pwd_reset_token_user ON password_reset_token(user_id);

-- ─── 7. User Consents ───
CREATE TABLE IF NOT EXISTS user_consent (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  UUID,
    user_id    UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    client_id  TEXT        NOT NULL,
    scopes     TEXT[]      NOT NULL DEFAULT '{}',
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_user_consent_user_client ON user_consent(user_id, client_id);
CREATE INDEX IF NOT EXISTS idx_user_consent_revoked_at ON user_consent(revoked_at);

-- ─── 8. Scopes ───
CREATE TABLE IF NOT EXISTS scope (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT        NOT NULL UNIQUE,
    description  TEXT,
    display_name TEXT,
    claims       TEXT[]      DEFAULT '{}',
    depends_on   TEXT,
    system       BOOLEAN     NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ─── 9. MFA Trusted Devices ───
CREATE TABLE IF NOT EXISTS mfa_trusted_device (
    id          BIGSERIAL   PRIMARY KEY,
    user_id     UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    device_hash TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_mfa_trusted_device_user ON mfa_trusted_device(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_mfa_trusted_device_user_hash ON mfa_trusted_device(user_id, device_hash);

-- ─── 9. MFA TOTP ───
CREATE TABLE IF NOT EXISTS mfa_totp (
    user_id        UUID        PRIMARY KEY REFERENCES app_user(id) ON DELETE CASCADE,
    secret_encrypted TEXT      NOT NULL,
    confirmed_at   TIMESTAMPTZ,
    last_used_at   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ─── 10. MFA Recovery Codes ───
CREATE TABLE IF NOT EXISTS mfa_recovery_code (
    id        BIGSERIAL   PRIMARY KEY,
    user_id   UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    code_hash TEXT        NOT NULL,
    used_at   TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, code_hash)
);

-- ─── 11. Sessions ───
CREATE TABLE IF NOT EXISTS sessions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    session_id_hash TEXT        NOT NULL UNIQUE,
    ip_address      INET,
    user_agent      TEXT,
    device_type     VARCHAR(20),
    browser         VARCHAR(100),
    os              VARCHAR(100),
    country_code    CHAR(2),
    country         VARCHAR(100),
    city            VARCHAR(100),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_activity   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    revoked_by      UUID,
    revoke_reason   TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_hash ON sessions(session_id_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(revoked_at, expires_at);

-- ─── 12. Password History ───
CREATE TABLE IF NOT EXISTS password_history (
    id         UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id    UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    hash       TEXT        NOT NULL,
    algorithm  TEXT        NOT NULL DEFAULT 'argon2id',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_password_history_user ON password_history(user_id);

-- ─── 13. Audit Log ───
CREATE TABLE IF NOT EXISTS audit_log (
    id          UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    event_type  TEXT        NOT NULL,
    actor_id    TEXT,
    actor_type  TEXT        NOT NULL DEFAULT 'system',
    target_id   TEXT,
    target_type TEXT,
    ip_address  INET,
    user_agent  TEXT,
    metadata    JSONB       DEFAULT '{}',
    result      TEXT        NOT NULL DEFAULT 'success',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log(target_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_type_created ON audit_log(event_type, created_at DESC);

-- ─── 14. Webhook Deliveries ───
CREATE TABLE IF NOT EXISTS webhook_delivery (
    id            UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
    webhook_id    TEXT        NOT NULL,
    event_type    TEXT        NOT NULL,
    payload       JSONB       NOT NULL,
    status        TEXT        NOT NULL DEFAULT 'pending',
    attempts      INT         NOT NULL DEFAULT 0,
    last_attempt  TIMESTAMPTZ,
    next_retry    TIMESTAMPTZ,
    http_status   INT,
    response_body TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Worker indexes (partial, avoid full scans)
CREATE INDEX IF NOT EXISTS idx_webhook_delivery_status ON webhook_delivery(status) WHERE status IN ('pending', 'failed');
CREATE INDEX IF NOT EXISTS idx_webhook_delivery_next ON webhook_delivery(next_retry) WHERE status IN ('pending', 'failed');
-- Admin panel indexes
CREATE INDEX IF NOT EXISTS idx_wd_admin_list ON webhook_delivery(webhook_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_wd_admin_status ON webhook_delivery(webhook_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_wd_admin_event ON webhook_delivery(webhook_id, event_type, created_at DESC);

-- ─── 15. WebAuthn Credentials ───
CREATE TABLE IF NOT EXISTS webauthn_credential (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL,
    user_id         UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    credential_id   BYTEA       NOT NULL,
    public_key      BYTEA       NOT NULL,
    aaguid          TEXT        NOT NULL DEFAULT '',
    sign_count      BIGINT      NOT NULL DEFAULT 0,
    transports      TEXT[]      NOT NULL DEFAULT '{}',
    user_verified   BOOLEAN     NOT NULL DEFAULT false,
    backup_eligible BOOLEAN     NOT NULL DEFAULT false,
    backup_state    BOOLEAN     NOT NULL DEFAULT false,
    name            TEXT        NOT NULL DEFAULT 'Passkey',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ,
    UNIQUE (tenant_id, credential_id)
);

CREATE INDEX IF NOT EXISTS idx_wa_cred_user ON webauthn_credential(tenant_id, user_id);

-- ─── 16. User Invitations ───
CREATE TABLE IF NOT EXISTS user_invitation (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID        NOT NULL,
    email       TEXT        NOT NULL,
    token_hash  TEXT        NOT NULL UNIQUE,
    status      TEXT        NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending','accepted','expired','revoked')),
    invited_by  UUID        NOT NULL REFERENCES app_user(id) ON DELETE RESTRICT,
    roles       TEXT[]      NOT NULL DEFAULT '{}',
    expires_at  TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_inv_tenant_status ON user_invitation(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_inv_token_hash ON user_invitation(token_hash);

-- ─── 17. Schema Migrations Tracking ───
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT        PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMIT;
