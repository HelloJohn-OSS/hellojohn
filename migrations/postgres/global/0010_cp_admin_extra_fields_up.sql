-- 0010_cp_admin_extra_fields_up.sql
-- Agrega columnas faltantes a cp_admin que el repo usa pero nunca se migraron.
-- Todas las columnas usan ADD COLUMN IF NOT EXISTS para ser idempotentes.

ALTER TABLE cp_admin
    ADD COLUMN IF NOT EXISTS disabled_at         TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS onboarding_completed BOOLEAN      NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS invite_token_hash   TEXT,
    ADD COLUMN IF NOT EXISTS invite_expires_at   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS status              TEXT         NOT NULL DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS created_by          UUID;

-- Índice para búsqueda por invite token (usado en GetByInviteTokenHash)
CREATE UNIQUE INDEX IF NOT EXISTS idx_cp_admin_invite_token ON cp_admin(invite_token_hash)
    WHERE invite_token_hash IS NOT NULL;
