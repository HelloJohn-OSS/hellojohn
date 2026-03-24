-- migrations/mysql/global_data_plane/0001_init_up.sql
-- Global Data Plane Schema for MySQL 8.0+: shared tables with logical tenant isolation.
-- Tenants are isolated via tenant_id column + application-level WHERE clauses.
-- WARNING: This schema is INCOMPATIBLE with the per-tenant isolated schema.
-- Each table has a tenant_id column that the isolated schema lacks.

-- ─── 1. Users ───
CREATE TABLE IF NOT EXISTS app_user (
  id               CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
  tenant_id        CHAR(36)     NOT NULL,
  email            VARCHAR(255) NOT NULL,
  email_verified   TINYINT(1)   NOT NULL DEFAULT 0,
  name             VARCHAR(255),
  given_name       VARCHAR(255),
  family_name      VARCHAR(255),
  picture          TEXT,
  locale           VARCHAR(10),
  language         VARCHAR(10)  DEFAULT '',
  status           VARCHAR(50)  NOT NULL DEFAULT 'active',
  profile          JSON         NOT NULL DEFAULT (JSON_OBJECT()),
  metadata         JSON         NOT NULL DEFAULT (JSON_OBJECT()),
  custom_data      JSON         NOT NULL DEFAULT (JSON_OBJECT()),
  disabled_at      DATETIME(6),
  disabled_reason  TEXT,
  disabled_until   DATETIME(6),
  source_client_id VARCHAR(255),
  created_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  UNIQUE KEY uq_gdp_user_tenant_email (tenant_id, email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_gdp_user_tenant ON app_user(tenant_id);
CREATE INDEX idx_gdp_user_created ON app_user(tenant_id, created_at DESC);

-- ─── 2. Identities ───
CREATE TABLE IF NOT EXISTS identity (
  id               CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
  tenant_id        CHAR(36)     NOT NULL,
  user_id          CHAR(36)     NOT NULL,
  provider         VARCHAR(100) NOT NULL,
  provider_user_id VARCHAR(255),
  email            VARCHAR(255),
  email_verified   TINYINT(1),
  password_hash    TEXT,
  data             JSON         DEFAULT (JSON_OBJECT()),
  created_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_gdp_identity_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_gdp_identity_tenant ON identity(tenant_id);
CREATE INDEX idx_gdp_identity_user ON identity(tenant_id, user_id);
CREATE UNIQUE INDEX ux_gdp_identity_provider_uid ON identity(tenant_id, provider, provider_user_id);
CREATE UNIQUE INDEX ux_gdp_identity_user_provider ON identity(tenant_id, user_id, provider);

-- ─── 3. Refresh Tokens ───
CREATE TABLE IF NOT EXISTS refresh_token (
  id             CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
  tenant_id      CHAR(36)     NOT NULL,
  user_id        CHAR(36)     NOT NULL,
  client_id_text VARCHAR(255),
  token_hash     VARCHAR(255) NOT NULL,
  issued_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  expires_at     DATETIME(6)  NOT NULL,
  rotated_from   CHAR(36)     NULL,
  revoked_at     DATETIME(6)  NULL,
  metadata       JSON         DEFAULT (JSON_OBJECT()),
  CONSTRAINT fk_gdp_token_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE,
  CONSTRAINT fk_gdp_token_rotated FOREIGN KEY (rotated_from) REFERENCES refresh_token(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_gdp_token_tenant ON refresh_token(tenant_id);
CREATE INDEX idx_gdp_token_user ON refresh_token(tenant_id, user_id);
CREATE UNIQUE INDEX ux_gdp_token_hash ON refresh_token(tenant_id, token_hash);

-- ─── 4. RBAC Roles ───
-- CRITICAL: PRIMARY KEY is (tenant_id, name) — not just name like in isolated schema.
CREATE TABLE IF NOT EXISTS rbac_role (
  id            CHAR(36)     DEFAULT (UUID()),
  tenant_id     CHAR(36)     NOT NULL,
  name          VARCHAR(255) NOT NULL,
  description   TEXT,
  permissions   JSON         NOT NULL DEFAULT (JSON_ARRAY()),
  inherits_from VARCHAR(255),
  system        TINYINT(1)   NOT NULL DEFAULT 0,
  created_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (tenant_id, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_gdp_rbac_role_tenant ON rbac_role(tenant_id);

-- ─── 5. RBAC User Roles ───
-- CRITICAL: FK references composite PK (tenant_id, name) on rbac_role.
CREATE TABLE IF NOT EXISTS rbac_user_role (
  tenant_id    CHAR(36)     NOT NULL,
  user_id      CHAR(36)     NOT NULL,
  role_name    VARCHAR(255) NOT NULL,
  assigned_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (tenant_id, user_id, role_name),
  CONSTRAINT fk_gdp_rbac_user_role FOREIGN KEY (tenant_id, role_name) REFERENCES rbac_role(tenant_id, name) ON DELETE CASCADE,
  CONSTRAINT fk_gdp_rbac_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_gdp_rbac_user_tenant ON rbac_user_role(tenant_id);
CREATE INDEX idx_gdp_rbac_user_uid ON rbac_user_role(tenant_id, user_id);

-- ─── 6. Email Verification Tokens ───
CREATE TABLE IF NOT EXISTS email_verification_token (
  id          CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
  tenant_id   CHAR(36)     NOT NULL,
  user_id     CHAR(36)     NOT NULL,
  token_hash  VARCHAR(255) NOT NULL,
  sent_to     VARCHAR(255) NOT NULL,
  expires_at  DATETIME(6)  NOT NULL,
  used_at     DATETIME(6),
  created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  ip          VARCHAR(45),
  CONSTRAINT fk_gdp_evt_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_gdp_evt_tenant ON email_verification_token(tenant_id);
CREATE INDEX idx_gdp_evt_user ON email_verification_token(tenant_id, user_id);
CREATE UNIQUE INDEX ux_gdp_evt_hash ON email_verification_token(tenant_id, token_hash);

-- ─── 7. Password Reset Tokens ───
CREATE TABLE IF NOT EXISTS password_reset_token (
  id          CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
  tenant_id   CHAR(36)     NOT NULL,
  user_id     CHAR(36)     NOT NULL,
  token_hash  VARCHAR(255) NOT NULL,
  sent_to     VARCHAR(255),
  expires_at  DATETIME(6)  NOT NULL,
  used_at     DATETIME(6),
  created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  ip          VARCHAR(45),
  CONSTRAINT fk_gdp_prt_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_gdp_prt_tenant ON password_reset_token(tenant_id);
CREATE UNIQUE INDEX ux_gdp_prt_hash ON password_reset_token(tenant_id, token_hash);
CREATE INDEX idx_gdp_prt_user ON password_reset_token(tenant_id, user_id);

-- ─── 8. MFA TOTP ───
CREATE TABLE IF NOT EXISTS mfa_totp (
  id           CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
  tenant_id    CHAR(36)     NOT NULL,
  user_id      CHAR(36)     NOT NULL,
  secret_enc   TEXT         NOT NULL,
  algorithm    VARCHAR(20)  NOT NULL DEFAULT 'SHA1',
  digits       INT          NOT NULL DEFAULT 6,
  period       INT          NOT NULL DEFAULT 30,
  enabled      TINYINT(1)   NOT NULL DEFAULT 0,
  verified_at  DATETIME(6),
  last_used_at DATETIME(6),
  created_at   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_gdp_mfa_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_gdp_mfa_tenant ON mfa_totp(tenant_id);
CREATE UNIQUE INDEX ux_gdp_mfa_user ON mfa_totp(tenant_id, user_id);

-- ─── 9. MFA Recovery Codes ───
CREATE TABLE IF NOT EXISTS mfa_recovery_code (
  id         CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
  tenant_id  CHAR(36)     NOT NULL,
  user_id    CHAR(36)     NOT NULL,
  code_hash  VARCHAR(255) NOT NULL,
  used_at    DATETIME(6),
  created_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_gdp_mrc_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_gdp_mrc_tenant ON mfa_recovery_code(tenant_id, user_id);
CREATE UNIQUE INDEX ux_gdp_mrc_code ON mfa_recovery_code(tenant_id, user_id, code_hash);

-- ─── 9b. MFA Trusted Devices ───
CREATE TABLE IF NOT EXISTS mfa_trusted_device (
  id          CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
  tenant_id   CHAR(36)     NOT NULL,
  user_id     CHAR(36)     NOT NULL,
  device_hash VARCHAR(255) NOT NULL,
  expires_at  DATETIME(6)  NOT NULL,
  created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_gdp_mtd_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_gdp_mtd_tenant ON mfa_trusted_device(tenant_id);
CREATE UNIQUE INDEX ux_gdp_mtd_user_hash ON mfa_trusted_device(tenant_id, user_id, device_hash);

-- ─── 10. User Consents ───
CREATE TABLE IF NOT EXISTS user_consent (
  id         CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
  tenant_id  CHAR(36)     NOT NULL,
  user_id    CHAR(36)     NOT NULL,
  client_id  VARCHAR(255) NOT NULL,
  scopes     JSON         NOT NULL DEFAULT (JSON_ARRAY()),
  granted_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  expires_at DATETIME(6),
  revoked_at DATETIME(6),
  CONSTRAINT fk_gdp_consent_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_gdp_consent_tenant ON user_consent(tenant_id);
CREATE UNIQUE INDEX ux_gdp_consent_user_client ON user_consent(tenant_id, user_id, client_id);

-- ─── 11. Sessions ───
CREATE TABLE IF NOT EXISTS sessions (
  id              CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
  tenant_id       CHAR(36)     NOT NULL,
  user_id         CHAR(36)     NOT NULL,
  session_id_hash VARCHAR(255) NOT NULL,
  ip_address      VARCHAR(45),
  user_agent      TEXT,
  device_type     VARCHAR(50),
  browser         VARCHAR(100),
  os              VARCHAR(100),
  country_code    VARCHAR(10),
  country         VARCHAR(100),
  city            VARCHAR(100),
  created_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  last_activity   DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  expires_at      DATETIME(6)  NOT NULL,
  revoked_at      DATETIME(6),
  revoked_by      VARCHAR(255),
  revoke_reason   TEXT,
  CONSTRAINT fk_gdp_session_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE UNIQUE INDEX ux_gdp_session_hash ON sessions(tenant_id, session_id_hash);
CREATE INDEX idx_gdp_session_user ON sessions(tenant_id, user_id);

-- ─── 12. Audit Log ───
CREATE TABLE IF NOT EXISTS audit_log (
  id          CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
  tenant_id   CHAR(36)     NOT NULL,
  event_type  VARCHAR(100) NOT NULL,
  actor_id    VARCHAR(255),
  actor_type  VARCHAR(50)  NOT NULL DEFAULT 'system',
  target_id   VARCHAR(255),
  target_type VARCHAR(100),
  ip_address  VARCHAR(45),
  user_agent  TEXT,
  metadata    JSON         DEFAULT (JSON_OBJECT()),
  result      VARCHAR(50)  NOT NULL DEFAULT 'success',
  created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_gdp_audit_tenant ON audit_log(tenant_id);
CREATE INDEX idx_gdp_audit_created ON audit_log(tenant_id, created_at DESC);
CREATE INDEX idx_gdp_audit_actor ON audit_log(tenant_id, actor_id);
CREATE INDEX idx_gdp_audit_target ON audit_log(tenant_id, target_id);

-- ─── 13. Webhooks (config + delivery outbox) ───
CREATE TABLE IF NOT EXISTS webhook (
  id         CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
  tenant_id  CHAR(36)     NOT NULL,
  url        TEXT         NOT NULL,
  events     JSON         NOT NULL DEFAULT (JSON_ARRAY()),
  secret_enc TEXT,
  enabled    TINYINT(1)   NOT NULL DEFAULT 1,
  created_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_gdp_webhook_tenant ON webhook(tenant_id);

CREATE TABLE IF NOT EXISTS webhook_delivery (
  id            CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
  tenant_id     CHAR(36)     NOT NULL,
  webhook_id    CHAR(36)     NOT NULL,
  event_type    VARCHAR(100) NOT NULL,
  payload       JSON         NOT NULL DEFAULT (JSON_OBJECT()),
  status        VARCHAR(50)  NOT NULL DEFAULT 'pending',
  attempts      INT          NOT NULL DEFAULT 0,
  last_attempt  DATETIME(6),
  next_retry    DATETIME(6),
  http_status   INT,
  response_body TEXT,
  created_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_gdp_wd_webhook FOREIGN KEY (webhook_id) REFERENCES webhook(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_gdp_wd_tenant ON webhook_delivery(tenant_id);

-- ─── 14. Invitations ───
CREATE TABLE IF NOT EXISTS invitation (
  id          CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
  tenant_id   CHAR(36)     NOT NULL,
  email       VARCHAR(255) NOT NULL,
  token_hash  VARCHAR(255) NOT NULL,
  status      VARCHAR(50)  NOT NULL DEFAULT 'pending',
  invited_by  CHAR(36),
  roles       JSON         NOT NULL DEFAULT (JSON_ARRAY()),
  expires_at  DATETIME(6)  NOT NULL,
  accepted_at DATETIME(6),
  created_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_gdp_invitation_tenant ON invitation(tenant_id);
CREATE UNIQUE INDEX ux_gdp_invitation_hash ON invitation(tenant_id, token_hash);

-- ─── 15. WebAuthn Credentials ───
CREATE TABLE IF NOT EXISTS webauthn_credential (
  id               CHAR(36)       NOT NULL DEFAULT (UUID()) PRIMARY KEY,
  tenant_id        CHAR(36)       NOT NULL,
  user_id          CHAR(36)       NOT NULL,
  credential_id    VARBINARY(1024) NOT NULL,
  public_key       VARBINARY(2048) NOT NULL,
  aaguid           VARBINARY(16),
  sign_count       BIGINT         NOT NULL DEFAULT 0,
  attestation_type VARCHAR(50),
  transports       JSON,
  user_verified    TINYINT(1)     NOT NULL DEFAULT 0,
  backup_eligible  TINYINT(1)     NOT NULL DEFAULT 0,
  backup_state     TINYINT(1)     NOT NULL DEFAULT 0,
  name             VARCHAR(255),
  created_at       DATETIME(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  last_used_at     DATETIME(6),
  CONSTRAINT fk_gdp_webauthn_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_gdp_webauthn_tenant ON webauthn_credential(tenant_id, user_id);
CREATE UNIQUE INDEX ux_gdp_webauthn_cred ON webauthn_credential(tenant_id, credential_id);

-- ─── 16. Password History ───
CREATE TABLE IF NOT EXISTS password_history (
  id         CHAR(36)     NOT NULL DEFAULT (UUID()) PRIMARY KEY,
  tenant_id  CHAR(36)     NOT NULL,
  user_id    CHAR(36)     NOT NULL,
  hash       TEXT         NOT NULL,
  algorithm  VARCHAR(50)  NOT NULL DEFAULT 'argon2id',
  created_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_gdp_ph_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
CREATE INDEX idx_gdp_ph_tenant ON password_history(tenant_id, user_id);
