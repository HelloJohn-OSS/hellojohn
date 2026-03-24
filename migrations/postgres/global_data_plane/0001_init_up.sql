-- migrations/postgres/global_data_plane/0001_gdp_init_up.sql
-- Global Data Plane Schema: shared tables with logical tenant isolation.
-- Tenants are isolated via tenant_id column + PostgreSQL Row-Level Security.
-- WARNING: This schema is INCOMPATIBLE with the per-tenant isolated schema.
-- Each table has a tenant_id column that the isolated schema lacks.

BEGIN;

-- ─── 1. Users ───
CREATE TABLE IF NOT EXISTS app_user (
  id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        UUID        NOT NULL,
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
  disabled_at      TIMESTAMPTZ,
  disabled_reason  TEXT,
  disabled_until   TIMESTAMPTZ,
  source_client_id TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, email)
);
CREATE INDEX IF NOT EXISTS idx_gdp_user_tenant ON app_user(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gdp_user_created ON app_user(tenant_id, created_at DESC);

-- ─── 2. Identities ───
CREATE TABLE IF NOT EXISTS identity (
  id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        UUID        NOT NULL,
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
CREATE INDEX IF NOT EXISTS idx_gdp_identity_tenant ON identity(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gdp_identity_user   ON identity(tenant_id, user_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_gdp_identity_provider_uid ON identity(tenant_id, provider, provider_user_id) WHERE provider_user_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_gdp_identity_user_provider ON identity(tenant_id, user_id, provider);

-- ─── 3. Refresh Tokens ───
CREATE TABLE IF NOT EXISTS refresh_token (
  id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      UUID        NOT NULL,
  user_id        UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  client_id_text TEXT,
  token_hash     TEXT        NOT NULL,
  issued_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at     TIMESTAMPTZ NOT NULL,
  rotated_from   UUID        NULL REFERENCES refresh_token(id) ON DELETE SET NULL,
  revoked_at     TIMESTAMPTZ NULL,
  metadata       JSONB       DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_gdp_token_tenant  ON refresh_token(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gdp_token_user    ON refresh_token(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_gdp_token_expires ON refresh_token(tenant_id, expires_at) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_gdp_token_hash ON refresh_token(tenant_id, token_hash);
CREATE INDEX IF NOT EXISTS idx_gdp_token_rotated ON refresh_token(tenant_id, rotated_from) WHERE rotated_from IS NOT NULL;

-- ─── 4. RBAC Roles ───
-- CRITICAL: PRIMARY KEY is (tenant_id, name) — not just name like in isolated schema.
CREATE TABLE IF NOT EXISTS rbac_role (
  id            UUID        DEFAULT gen_random_uuid(),
  tenant_id     UUID        NOT NULL,
  name          TEXT        NOT NULL,
  description   TEXT,
  permissions   TEXT[]      NOT NULL DEFAULT '{}',
  inherits_from TEXT,
  system        BOOLEAN     NOT NULL DEFAULT false,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS idx_gdp_rbac_role_tenant ON rbac_role(tenant_id);

-- ─── 5. RBAC User Roles ───
-- CRITICAL: FK references composite PK (tenant_id, name) on rbac_role.
CREATE TABLE IF NOT EXISTS rbac_user_role (
  tenant_id    UUID        NOT NULL,
  user_id      UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  role_name    TEXT        NOT NULL,
  assigned_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id, role_name),
  FOREIGN KEY (tenant_id, role_name) REFERENCES rbac_role(tenant_id, name) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_gdp_rbac_user_tenant ON rbac_user_role(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gdp_rbac_user_uid    ON rbac_user_role(tenant_id, user_id);

-- ─── 6. Email Verification Tokens ───
CREATE TABLE IF NOT EXISTS email_verification_token (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID        NOT NULL,
  user_id     UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  token_hash  TEXT        NOT NULL,
  sent_to     TEXT        NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  used_at     TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  ip          VARCHAR(45)
);
CREATE INDEX IF NOT EXISTS idx_gdp_evt_tenant ON email_verification_token(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gdp_evt_user   ON email_verification_token(tenant_id, user_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_gdp_evt_hash ON email_verification_token(tenant_id, token_hash);

-- ─── 7. Password Reset Tokens ───
CREATE TABLE IF NOT EXISTS password_reset_token (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID        NOT NULL,
  user_id     UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  token_hash  TEXT        NOT NULL,
  sent_to     TEXT,
  expires_at  TIMESTAMPTZ NOT NULL,
  used_at     TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  ip          VARCHAR(45)
);
CREATE INDEX IF NOT EXISTS idx_gdp_prt_tenant ON password_reset_token(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_gdp_prt_hash ON password_reset_token(tenant_id, token_hash);
CREATE INDEX IF NOT EXISTS idx_gdp_prt_user ON password_reset_token(tenant_id, user_id);

-- ─── 8. MFA TOTP ───
CREATE TABLE IF NOT EXISTS mfa_totp (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID        NOT NULL,
  user_id     UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  secret_enc  TEXT        NOT NULL,
  algorithm   TEXT        NOT NULL DEFAULT 'SHA1',
  digits      INT         NOT NULL DEFAULT 6,
  period      INT         NOT NULL DEFAULT 30,
  enabled     BOOLEAN     NOT NULL DEFAULT false,
  verified_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,  -- LOW-11: TOTP replay detection
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_gdp_mfa_tenant ON mfa_totp(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_gdp_mfa_user ON mfa_totp(tenant_id, user_id);

-- ─── 9. MFA Recovery Codes ───
CREATE TABLE IF NOT EXISTS mfa_recovery_code (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  UUID        NOT NULL,
  user_id    UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  code_hash  TEXT        NOT NULL,
  used_at    TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_gdp_mrc_tenant ON mfa_recovery_code(tenant_id, user_id);
-- LOW-12: unique index to prevent duplicate code_hash per user
CREATE UNIQUE INDEX IF NOT EXISTS ux_gdp_mrc_code ON mfa_recovery_code(tenant_id, user_id, code_hash);

-- ─── 9b. MFA Trusted Devices ───
CREATE TABLE IF NOT EXISTS mfa_trusted_device (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID        NOT NULL,
  user_id     UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  device_hash TEXT        NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_gdp_mtd_tenant ON mfa_trusted_device(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_gdp_mtd_user_hash ON mfa_trusted_device(tenant_id, user_id, device_hash);

-- ─── 10. User Consents ───
CREATE TABLE IF NOT EXISTS user_consent (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  UUID        NOT NULL,
  user_id    UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  client_id  TEXT        NOT NULL,
  scopes     TEXT[]      NOT NULL DEFAULT '{}',
  granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_gdp_consent_tenant ON user_consent(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_gdp_consent_user_client ON user_consent(tenant_id, user_id, client_id);

-- ─── 11. Sessions ───
CREATE TABLE IF NOT EXISTS sessions (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID        NOT NULL,
  user_id         UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  session_id_hash TEXT        NOT NULL,
  ip_address      INET,
  user_agent      TEXT,
  device_type     TEXT,
  browser         TEXT,
  os              TEXT,
  country_code    TEXT,
  country         TEXT,
  city            TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_activity   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at      TIMESTAMPTZ NOT NULL,
  revoked_at      TIMESTAMPTZ,
  revoked_by      TEXT,
  revoke_reason   TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_gdp_session_hash ON sessions(tenant_id, session_id_hash);
CREATE INDEX IF NOT EXISTS idx_gdp_session_user ON sessions(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_gdp_session_active ON sessions(tenant_id, user_id) WHERE revoked_at IS NULL;

-- ─── 12. Audit Log ───
CREATE TABLE IF NOT EXISTS audit_log (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID        NOT NULL,
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
CREATE INDEX IF NOT EXISTS idx_gdp_audit_tenant  ON audit_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gdp_audit_created ON audit_log(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gdp_audit_actor   ON audit_log(tenant_id, actor_id);
CREATE INDEX IF NOT EXISTS idx_gdp_audit_target  ON audit_log(tenant_id, target_id);

-- ─── 13. Webhooks (config + delivery outbox) ───
CREATE TABLE IF NOT EXISTS webhook (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  UUID        NOT NULL,
  url        TEXT        NOT NULL,
  events     TEXT[]      NOT NULL DEFAULT '{}',
  secret_enc TEXT,
  enabled    BOOLEAN     NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_gdp_webhook_tenant ON webhook(tenant_id);

CREATE TABLE IF NOT EXISTS webhook_delivery (
  id            UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID            NOT NULL,
  webhook_id    UUID            NOT NULL REFERENCES webhook(id) ON DELETE CASCADE,
  event_type    TEXT            NOT NULL,
  payload       JSONB           NOT NULL DEFAULT '{}',
  status        TEXT            NOT NULL DEFAULT 'pending',
  attempts      INT             NOT NULL DEFAULT 0,
  last_attempt  TIMESTAMPTZ,
  next_retry    TIMESTAMPTZ,
  http_status   INT,
  response_body TEXT,
  created_at    TIMESTAMPTZ     NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_gdp_wd_tenant ON webhook_delivery(tenant_id);
CREATE INDEX IF NOT EXISTS idx_gdp_wd_pending ON webhook_delivery(tenant_id, status, next_retry) WHERE status IN ('pending', 'failed');

-- ─── 14. Invitations ───
CREATE TABLE IF NOT EXISTS invitation (
  id          UUID             PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID             NOT NULL,
  email       TEXT             NOT NULL,
  token_hash  TEXT             NOT NULL,
  status      TEXT             NOT NULL DEFAULT 'pending',
  invited_by  UUID,
  roles       TEXT[]           NOT NULL DEFAULT '{}',
  expires_at  TIMESTAMPTZ      NOT NULL,
  accepted_at TIMESTAMPTZ,
  created_at  TIMESTAMPTZ      NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ      NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_gdp_invitation_tenant ON invitation(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_gdp_invitation_hash ON invitation(tenant_id, token_hash);

-- ─── 15. WebAuthn Credentials ───
CREATE TABLE IF NOT EXISTS webauthn_credential (
  id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        UUID        NOT NULL,
  user_id          UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  credential_id    BYTEA       NOT NULL,
  public_key       BYTEA       NOT NULL,
  aaguid           BYTEA,
  sign_count       BIGINT      NOT NULL DEFAULT 0,
  attestation_type TEXT,
  transports       TEXT[],
  user_verified    BOOLEAN     NOT NULL DEFAULT false,
  backup_eligible  BOOLEAN     NOT NULL DEFAULT false,
  backup_state     BOOLEAN     NOT NULL DEFAULT false,
  name             TEXT,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_gdp_webauthn_tenant ON webauthn_credential(tenant_id, user_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_gdp_webauthn_cred ON webauthn_credential(tenant_id, credential_id);

-- ─── 16. Password History ───
CREATE TABLE IF NOT EXISTS password_history (
  id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  UUID        NOT NULL,
  user_id    UUID        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  hash       TEXT        NOT NULL,
  algorithm  TEXT        NOT NULL DEFAULT 'argon2id',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_gdp_ph_tenant ON password_history(tenant_id, user_id);

-- ─── Row-Level Security ───
-- Defense-in-depth: RLS enforces tenant isolation at the DB engine level.
-- app queries MUST also include WHERE tenant_id = $X (not rely on RLS alone).
-- SET LOCAL app.tenant_id = '<uuid>' must be called in every transaction.
-- current_setting('app.tenant_id', true) returns NULL when not set → no rows visible.

ALTER TABLE app_user              ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity              ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_token         ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbac_role             ENABLE ROW LEVEL SECURITY;
ALTER TABLE rbac_user_role        ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_verification_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_reset_token  ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_totp              ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_recovery_code     ENABLE ROW LEVEL SECURITY;
ALTER TABLE mfa_trusted_device    ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_consent          ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions              ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log             ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook               ENABLE ROW LEVEL SECURITY;
ALTER TABLE webhook_delivery      ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitation            ENABLE ROW LEVEL SECURITY;
ALTER TABLE webauthn_credential   ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_history      ENABLE ROW LEVEL SECURITY;

-- FORCE ROW LEVEL SECURITY ensures RLS policies are always applied, even when the
-- application DB user is the table owner. Without FORCE, table owners bypass policies,
-- which means a misconfigured DSN or non-owner role could expose all tenants' data.
ALTER TABLE app_user              FORCE ROW LEVEL SECURITY;
ALTER TABLE identity              FORCE ROW LEVEL SECURITY;
ALTER TABLE refresh_token         FORCE ROW LEVEL SECURITY;
ALTER TABLE rbac_role             FORCE ROW LEVEL SECURITY;
ALTER TABLE rbac_user_role        FORCE ROW LEVEL SECURITY;
ALTER TABLE email_verification_token FORCE ROW LEVEL SECURITY;
ALTER TABLE password_reset_token  FORCE ROW LEVEL SECURITY;
ALTER TABLE mfa_totp              FORCE ROW LEVEL SECURITY;
ALTER TABLE mfa_recovery_code     FORCE ROW LEVEL SECURITY;
ALTER TABLE mfa_trusted_device    FORCE ROW LEVEL SECURITY;
ALTER TABLE user_consent          FORCE ROW LEVEL SECURITY;
ALTER TABLE sessions              FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_log             FORCE ROW LEVEL SECURITY;
ALTER TABLE webhook               FORCE ROW LEVEL SECURITY;
ALTER TABLE webhook_delivery      FORCE ROW LEVEL SECURITY;
ALTER TABLE invitation            FORCE ROW LEVEL SECURITY;
ALTER TABLE webauthn_credential   FORCE ROW LEVEL SECURITY;
ALTER TABLE password_history      FORCE ROW LEVEL SECURITY;

-- RLS Policies (one per table, same pattern)
CREATE POLICY gdp_tenant_isolation ON app_user
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY gdp_tenant_isolation ON identity
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY gdp_tenant_isolation ON refresh_token
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY gdp_tenant_isolation ON rbac_role
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY gdp_tenant_isolation ON rbac_user_role
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY gdp_tenant_isolation ON email_verification_token
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY gdp_tenant_isolation ON password_reset_token
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY gdp_tenant_isolation ON mfa_totp
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY gdp_tenant_isolation ON mfa_recovery_code
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY gdp_tenant_isolation ON mfa_trusted_device
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY gdp_tenant_isolation ON user_consent
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY gdp_tenant_isolation ON sessions
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY gdp_tenant_isolation ON audit_log
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY gdp_tenant_isolation ON webhook
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY gdp_tenant_isolation ON webhook_delivery
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY gdp_tenant_isolation ON invitation
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY gdp_tenant_isolation ON webauthn_credential
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);
CREATE POLICY gdp_tenant_isolation ON password_history
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

COMMIT;
