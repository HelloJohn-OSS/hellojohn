-- Phase 10A: WebAuthn/passkey credentials
CREATE TABLE IF NOT EXISTS webauthn_credential (
    id              CHAR(36)        PRIMARY KEY DEFAULT (UUID()),
    tenant_id       CHAR(36)        NOT NULL,
    user_id         CHAR(36)        NOT NULL,
    credential_id   VARBINARY(1024) NOT NULL,
    public_key      BLOB            NOT NULL,
    aaguid          VARCHAR(100)    NOT NULL DEFAULT '',
    sign_count      BIGINT UNSIGNED NOT NULL DEFAULT 0,
    transports      JSON            NOT NULL DEFAULT (JSON_ARRAY()),
    user_verified   TINYINT(1)      NOT NULL DEFAULT 0,
    backup_eligible TINYINT(1)      NOT NULL DEFAULT 0,
    backup_state    TINYINT(1)      NOT NULL DEFAULT 0,
    name            VARCHAR(255)    NOT NULL DEFAULT 'Passkey',
    created_at      DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_used_at    DATETIME(6),
    UNIQUE KEY uq_wa_tenant_cred (tenant_id, credential_id),
    INDEX idx_wa_cred_user (tenant_id, user_id),
    FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
