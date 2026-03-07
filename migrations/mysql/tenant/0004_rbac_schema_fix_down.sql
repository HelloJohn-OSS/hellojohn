-- Rollback migration for RBAC schema fix (MySQL)

-- Remove added columns (only if they were added by this migration)
-- Note: This is destructive and should be used with caution

DELIMITER //

CREATE PROCEDURE rollback_rbac_schema()
BEGIN
    DECLARE col_exists INT DEFAULT 0;

    -- Drop id column if exists
    SELECT COUNT(*) INTO col_exists
    FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'rbac_role' AND column_name = 'id';
    IF col_exists > 0 THEN
        ALTER TABLE rbac_role DROP COLUMN id;
    END IF;

    -- Drop inherits_from column if exists
    SELECT COUNT(*) INTO col_exists
    FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'rbac_role' AND column_name = 'inherits_from';
    IF col_exists > 0 THEN
        ALTER TABLE rbac_role DROP COLUMN inherits_from;
    END IF;

    -- Drop system column if exists
    SELECT COUNT(*) INTO col_exists
    FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'rbac_role' AND column_name = 'system';
    IF col_exists > 0 THEN
        ALTER TABLE rbac_role DROP COLUMN system;
    END IF;

    -- Drop updated_at column if exists
    SELECT COUNT(*) INTO col_exists
    FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'rbac_role' AND column_name = 'updated_at';
    IF col_exists > 0 THEN
        ALTER TABLE rbac_role DROP COLUMN updated_at;
    END IF;
END //

DELIMITER ;

CALL rollback_rbac_schema();
DROP PROCEDURE IF EXISTS rollback_rbac_schema;

-- Remove migration record
DELETE FROM schema_migrations WHERE version = '0004_rbac_schema_fix';
