-- Rollback migration for RBAC schema fix

BEGIN;

-- Remove added columns (only if they were added by this migration)
ALTER TABLE rbac_role DROP COLUMN IF EXISTS id;
ALTER TABLE rbac_role DROP COLUMN IF EXISTS inherits_from;
ALTER TABLE rbac_role DROP COLUMN IF EXISTS system;
ALTER TABLE rbac_role DROP COLUMN IF EXISTS updated_at;

-- Remove migration record
DELETE FROM schema_migrations WHERE version = '0004_rbac_schema_fix';

COMMIT;
