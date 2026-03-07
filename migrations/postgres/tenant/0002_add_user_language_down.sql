-- Rollback: Remove language field from app_user

BEGIN;

ALTER TABLE app_user DROP COLUMN IF EXISTS language;

COMMIT;
