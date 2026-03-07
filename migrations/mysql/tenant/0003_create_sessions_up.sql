-- Migration: Create sessions table for active session tracking (MySQL)
-- Allows managing, listing and revoking sessions from admin panel

-- Sessions table was already created in 0001_init for MySQL
-- This migration exists for compatibility with PostgreSQL migration numbering

-- Ensure sessions table exists (idempotent)
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
    UNIQUE KEY ux_session_hash (session_id_hash),
    INDEX idx_session_user (user_id, created_at DESC),
    INDEX idx_session_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Add foreign key if not exists (for databases upgraded from old schema)
-- MySQL doesn't have ADD CONSTRAINT IF NOT EXISTS, handled with procedure
DELIMITER //
CREATE PROCEDURE add_session_fk()
BEGIN
    DECLARE fk_exists INT DEFAULT 0;
    SELECT COUNT(*) INTO fk_exists
    FROM information_schema.table_constraints
    WHERE table_schema = DATABASE()
      AND table_name = 'sessions'
      AND constraint_name = 'fk_session_user';
    
    IF fk_exists = 0 THEN
        ALTER TABLE sessions
        ADD CONSTRAINT fk_session_user FOREIGN KEY (user_id)
        REFERENCES app_user(id) ON DELETE CASCADE;
    END IF;
END //
DELIMITER ;

CALL add_session_fk();
DROP PROCEDURE IF EXISTS add_session_fk;

-- Record migration
INSERT IGNORE INTO schema_migrations (version, applied_at) VALUES ('0003_create_sessions', NOW());
