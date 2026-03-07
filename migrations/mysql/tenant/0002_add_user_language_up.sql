-- Migration: Add language field to app_user (MySQL)
-- Applied to each tenant's isolated database.

-- Add language column if it doesn't exist
-- MySQL doesn't have ADD COLUMN IF NOT EXISTS, use stored procedure
DELIMITER //
CREATE PROCEDURE add_language_column()
BEGIN
    DECLARE col_exists INT DEFAULT 0;
    SELECT COUNT(*) INTO col_exists
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'app_user'
      AND column_name = 'language';
    
    IF col_exists = 0 THEN
        ALTER TABLE app_user ADD COLUMN language VARCHAR(10) DEFAULT '';
    END IF;
END //
DELIMITER ;

CALL add_language_column();
DROP PROCEDURE IF EXISTS add_language_column;

-- Record migration
INSERT IGNORE INTO schema_migrations (version, applied_at) VALUES ('0002_add_user_language', NOW());
