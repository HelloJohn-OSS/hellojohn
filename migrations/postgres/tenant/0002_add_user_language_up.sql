-- Migration: Add language field to app_user
-- Applied to each tenant's isolated database/schema.

BEGIN;

-- Add language column to app_user for user-preferred language
-- Empty string = use tenant's default language
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS language TEXT DEFAULT '';

COMMIT;
