-- MySQL Tenant Schema v2
-- Applied to each tenant's isolated database.
-- Consolidated schema for tenant databases.

-- 1. Users & Profiles
CREATE TABLE IF NOT EXISTS app_user (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    email VARCHAR(320) NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    name VARCHAR(255),
    given_name VARCHAR(255),
    family_name VARCHAR(255),
    picture TEXT,
    locale VARCHAR(10),
    language VARCHAR(10) DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    profile JSON NOT NULL DEFAULT (JSON_OBJECT()),
    metadata JSON NOT NULL DEFAULT (JSON_OBJECT()),
    source_client_id VARCHAR(100),
    disabled_at DATETIME(6),
    disabled_reason TEXT,
    disabled_until DATETIME(6),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY ux_app_user_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Identities (Auth Providers)
CREATE TABLE IF NOT EXISTS identity (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    user_id CHAR(36) NOT NULL,
    provider VARCHAR(50) NOT NULL, -- 'password', 'google', 'github', etc.
    provider_user_id VARCHAR(255),
    email VARCHAR(320),
    email_verified BOOLEAN,
    password_hash TEXT,
    data JSON DEFAULT (JSON_OBJECT()), -- Extra provider data
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_identity_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE,
    INDEX idx_identity_user (user_id),
    UNIQUE KEY ux_identity_provider_uid (provider, provider_user_id),
    UNIQUE KEY ux_identity_user_provider (user_id, provider)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Refresh Tokens
CREATE TABLE IF NOT EXISTS refresh_token (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    user_id CHAR(36) NOT NULL,
    client_id_text VARCHAR(100),
    token_hash VARCHAR(255) NOT NULL,
    issued_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at DATETIME(6) NOT NULL,
    rotated_from CHAR(36) NULL,
    revoked_at DATETIME(6) NULL,
    metadata JSON DEFAULT (JSON_OBJECT()),
    CONSTRAINT fk_refresh_token_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE,
    CONSTRAINT fk_refresh_token_rotated FOREIGN KEY (rotated_from) REFERENCES refresh_token(id) ON DELETE SET NULL,
    UNIQUE KEY ux_refresh_token_hash (token_hash),
    INDEX idx_refresh_token_user (user_id),
    INDEX idx_refresh_token_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. RBAC (Role Based Access Control)
CREATE TABLE IF NOT EXISTS rbac_role (
    id CHAR(36) DEFAULT (UUID()),
    name VARCHAR(100) PRIMARY KEY,
    description TEXT,
    permissions JSON NOT NULL DEFAULT (JSON_ARRAY()),
    inherits_from VARCHAR(100),
    system BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS rbac_user_role (
    user_id CHAR(36) NOT NULL,
    role_name VARCHAR(100) NOT NULL,
    assigned_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (user_id, role_name),
    CONSTRAINT fk_user_role_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_role_role FOREIGN KEY (role_name) REFERENCES rbac_role(name) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Email Verification Tokens
CREATE TABLE IF NOT EXISTS email_verification_token (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    user_id CHAR(36) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    sent_to VARCHAR(320) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at DATETIME(6) NOT NULL,
    used_at DATETIME(6),
    CONSTRAINT fk_email_verif_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE,
    UNIQUE KEY ux_email_verif_hash (token_hash),
    INDEX idx_email_verif_expires (expires_at),
    INDEX idx_email_verif_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. Password Reset Tokens
CREATE TABLE IF NOT EXISTS password_reset_token (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    user_id CHAR(36) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    sent_to VARCHAR(320) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at DATETIME(6) NOT NULL,
    used_at DATETIME(6),
    CONSTRAINT fk_pwd_reset_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE,
    UNIQUE KEY ux_pwd_reset_hash (token_hash),
    INDEX idx_pwd_reset_expires (expires_at),
    INDEX idx_pwd_reset_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. User Consents
CREATE TABLE IF NOT EXISTS user_consent (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    tenant_id CHAR(36),
    user_id CHAR(36) NOT NULL,
    client_id VARCHAR(100) NOT NULL,
    scopes JSON NOT NULL DEFAULT (JSON_ARRAY()),
    granted_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    revoked_at DATETIME(6),
    CONSTRAINT fk_consent_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE,
    UNIQUE KEY ux_consent_user_client (user_id, client_id),
    INDEX idx_consent_revoked (revoked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 8. Scopes
CREATE TABLE IF NOT EXISTS scope (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    tenant_id CHAR(36),
    name VARCHAR(100) NOT NULL,
    description TEXT,
    display_name VARCHAR(255),
    claims JSON DEFAULT (JSON_ARRAY()),
    depends_on VARCHAR(100),
    system BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY ux_scope_tenant_name (tenant_id, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 9. MFA TOTP
CREATE TABLE IF NOT EXISTS mfa_totp (
    user_id CHAR(36) PRIMARY KEY,
    secret_encrypted TEXT NOT NULL,
    confirmed_at DATETIME(6),
    last_used_at DATETIME(6),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_mfa_totp_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 10. MFA Recovery Codes
CREATE TABLE IF NOT EXISTS mfa_recovery_code (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    used_at DATETIME(6),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_recovery_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE,
    UNIQUE KEY ux_recovery_user_hash (user_id, code_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 11. MFA Trusted Devices
CREATE TABLE IF NOT EXISTS mfa_trusted_device (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    device_hash VARCHAR(255) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_trusted_device_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE,
    UNIQUE KEY ux_trusted_device (user_id, device_hash),
    INDEX idx_trusted_device_user (user_id),
    INDEX idx_trusted_device_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 12. Sessions
CREATE TABLE IF NOT EXISTS sessions (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    user_id CHAR(36) NOT NULL,
    session_id_hash VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_type VARCHAR(20),
    browser VARCHAR(100),
    os VARCHAR(100),
    country_code CHAR(2),
    country VARCHAR(100),
    city VARCHAR(100),
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_activity DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at DATETIME(6) NOT NULL,
    revoked_at DATETIME(6),
    revoked_by VARCHAR(100),
    revoke_reason TEXT,
    CONSTRAINT fk_session_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE,
    UNIQUE KEY ux_session_hash (session_id_hash),
    INDEX idx_session_user (user_id, created_at DESC),
    INDEX idx_session_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 13. Schema Migrations Tracking
CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(100) PRIMARY KEY,
    applied_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Record this migration
INSERT IGNORE INTO schema_migrations (version, applied_at) VALUES ('0001_init', NOW());
