-- Migration to fix RBAC schema alignment (MySQL)
-- Adds missing columns to rbac_role table for existing databases

-- Add missing columns using stored procedures (MySQL doesn't have ADD COLUMN IF NOT EXISTS)
DELIMITER //

CREATE PROCEDURE fix_rbac_schema()
BEGIN
    DECLARE col_id_exists INT DEFAULT 0;
    DECLARE col_inherits_exists INT DEFAULT 0;
    DECLARE col_system_exists INT DEFAULT 0;
    DECLARE col_updated_exists INT DEFAULT 0;
    DECLARE col_perms_exists INT DEFAULT 0;

    -- Check id column
    SELECT COUNT(*) INTO col_id_exists
    FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'rbac_role' AND column_name = 'id';
    
    IF col_id_exists = 0 THEN
        ALTER TABLE rbac_role ADD COLUMN id CHAR(36) DEFAULT (UUID());
    END IF;

    -- Check inherits_from column
    SELECT COUNT(*) INTO col_inherits_exists
    FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'rbac_role' AND column_name = 'inherits_from';
    
    IF col_inherits_exists = 0 THEN
        ALTER TABLE rbac_role ADD COLUMN inherits_from VARCHAR(100);
    END IF;

    -- Check system column
    SELECT COUNT(*) INTO col_system_exists
    FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'rbac_role' AND column_name = 'system';
    
    IF col_system_exists = 0 THEN
        ALTER TABLE rbac_role ADD COLUMN system BOOLEAN NOT NULL DEFAULT FALSE;
    END IF;

    -- Check updated_at column
    SELECT COUNT(*) INTO col_updated_exists
    FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'rbac_role' AND column_name = 'updated_at';
    
    IF col_updated_exists = 0 THEN
        ALTER TABLE rbac_role ADD COLUMN updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6);
    END IF;

    -- Check permissions column (ensure it exists as JSON)
    SELECT COUNT(*) INTO col_perms_exists
    FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'rbac_role' AND column_name = 'permissions';
    
    IF col_perms_exists = 0 THEN
        ALTER TABLE rbac_role ADD COLUMN permissions JSON NOT NULL DEFAULT (JSON_ARRAY());
    END IF;
END //

DELIMITER ;

CALL fix_rbac_schema();
DROP PROCEDURE IF EXISTS fix_rbac_schema;

-- Record migration
INSERT IGNORE INTO schema_migrations (version, applied_at) VALUES ('0004_rbac_schema_fix', NOW());
