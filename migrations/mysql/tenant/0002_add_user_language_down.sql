-- Rollback: Remove language field from app_user (MySQL)

ALTER TABLE app_user DROP COLUMN IF EXISTS language;

DELETE FROM schema_migrations WHERE version = '0002_add_user_language';
