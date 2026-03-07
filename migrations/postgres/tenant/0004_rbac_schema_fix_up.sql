-- Migration to fix RBAC schema alignment
-- Adds missing columns to rbac_role table for existing databases

BEGIN;

-- Add missing columns to rbac_role if they don't exist
ALTER TABLE rbac_role ADD COLUMN IF NOT EXISTS id UUID DEFAULT gen_random_uuid();
ALTER TABLE rbac_role ADD COLUMN IF NOT EXISTS inherits_from TEXT;
ALTER TABLE rbac_role ADD COLUMN IF NOT EXISTS system BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE rbac_role ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Ensure permissions column exists and has correct type
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'rbac_role' AND column_name = 'permissions'
    ) THEN
        ALTER TABLE rbac_role ADD COLUMN permissions TEXT[] NOT NULL DEFAULT '{}';
    END IF;
END $$;

-- Record migration
INSERT INTO schema_migrations (version, applied_at)
VALUES ('0004_rbac_schema_fix', NOW())
ON CONFLICT (version) DO NOTHING;

COMMIT;
