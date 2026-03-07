-- Phase 10C: user invitations
CREATE TABLE IF NOT EXISTS user_invitation (
    id          CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    tenant_id   CHAR(36) NOT NULL,
    email       VARCHAR(255) NOT NULL,
    token_hash  VARCHAR(64) NOT NULL UNIQUE,
    status      ENUM('pending','accepted','expired','revoked') NOT NULL DEFAULT 'pending',
    invited_by  CHAR(36) NOT NULL,
    roles       JSON NOT NULL DEFAULT (JSON_ARRAY()),
    expires_at  DATETIME(6) NOT NULL,
    accepted_at DATETIME(6),
    created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    INDEX idx_inv_tenant_status (tenant_id, status),
    UNIQUE KEY uq_inv_token_hash (token_hash),
    FOREIGN KEY (invited_by) REFERENCES app_user(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

