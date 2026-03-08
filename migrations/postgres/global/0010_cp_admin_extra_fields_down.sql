-- 0010_cp_admin_extra_fields_down.sql
DROP INDEX IF EXISTS idx_cp_admin_invite_token;

ALTER TABLE cp_admin
    DROP COLUMN IF EXISTS created_by,
    DROP COLUMN IF EXISTS status,
    DROP COLUMN IF EXISTS invite_expires_at,
    DROP COLUMN IF EXISTS invite_token_hash,
    DROP COLUMN IF EXISTS onboarding_completed,
    DROP COLUMN IF EXISTS disabled_at;
