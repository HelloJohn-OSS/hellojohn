-- Consolidated Tenant Schema v2
-- Applied to each tenant's isolated database/schema.
-- This is the complete schema for tenant databases.

BEGIN;

-- 1. Users & Profiles
CREATE TABLE IF NOT EXISTS app_user (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL,
  email_verified BOOLEAN NOT NULL DEFAULT false,
  name TEXT,
  given_name TEXT,
  family_name TEXT,
  picture TEXT,
  locale TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  profile JSONB NOT NULL DEFAULT '{}',
  metadata JSONB NOT NULL DEFAULT '{}',
  disabled_at TIMESTAMPTZ,
  disabled_reason TEXT,
  disabled_until TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (email)
);

-- Ensure all profile columns exist for legacy databases
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS name TEXT;
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS given_name TEXT;
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS family_name TEXT;
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS picture TEXT;
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS locale TEXT;
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS disabled_until TIMESTAMPTZ;
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS source_client_id TEXT;
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS language TEXT DEFAULT '';

-- 2. Identities (Auth Providers)
CREATE TABLE IF NOT EXISTS identity (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  provider TEXT NOT NULL, -- 'password', 'google', 'github', etc.
  provider_user_id TEXT,
  email TEXT,
  email_verified BOOLEAN,
  password_hash TEXT,
  data JSONB DEFAULT '{}', -- Extra provider data
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_identity_user ON identity(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_identity_provider_uid ON identity(provider, provider_user_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_identity_user_provider ON identity(user_id, provider);

-- 3. Sessions / Refresh Tokens
CREATE TABLE IF NOT EXISTS refresh_token (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  client_id_text TEXT,
  token_hash TEXT NOT NULL UNIQUE,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  rotated_from UUID NULL REFERENCES refresh_token(id) ON DELETE SET NULL,
  revoked_at TIMESTAMPTZ NULL,
  metadata JSONB DEFAULT '{}'
);

-- Ensure columns exist for legacy databases
ALTER TABLE refresh_token ADD COLUMN IF NOT EXISTS client_id_text TEXT;

-- Migrate old client_id to client_id_text if exists
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'refresh_token' AND column_name = 'client_id') THEN
        UPDATE refresh_token SET client_id_text = client_id WHERE client_id_text IS NULL AND client_id IS NOT NULL;
        ALTER TABLE refresh_token DROP COLUMN IF EXISTS client_id;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_refresh_token_user ON refresh_token(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_token_expires ON refresh_token(expires_at) WHERE revoked_at IS NULL;

-- 4. RBAC (Role Based Access Control)
CREATE TABLE IF NOT EXISTS rbac_role (
  id UUID DEFAULT gen_random_uuid(),
  name TEXT PRIMARY KEY,
  description TEXT,
  permissions TEXT[] NOT NULL DEFAULT '{}',
  inherits_from TEXT,
  system BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rbac_user_role (
  user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  role_name TEXT NOT NULL REFERENCES rbac_role(name) ON DELETE CASCADE,
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, role_name)
);

-- 5. Email Flows
CREATE TABLE IF NOT EXISTS email_verification_token (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  token_hash BYTEA NOT NULL UNIQUE,
  sent_to TEXT NOT NULL,
  ip INET,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_email_verif_token_expires_at ON email_verification_token (expires_at);
CREATE INDEX IF NOT EXISTS idx_email_verif_token_user ON email_verification_token (user_id);

CREATE TABLE IF NOT EXISTS password_reset_token (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  token_hash BYTEA NOT NULL UNIQUE,
  sent_to TEXT NOT NULL,
  ip INET,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pwd_reset_token_expires_at ON password_reset_token (expires_at);
CREATE INDEX IF NOT EXISTS idx_pwd_reset_token_user ON password_reset_token (user_id);

-- 6. User Consents
CREATE TABLE IF NOT EXISTS user_consent (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  client_id_text TEXT NOT NULL,
  granted_scopes TEXT[] NOT NULL,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_user_consent_user_client ON user_consent (user_id, client_id_text);
CREATE INDEX IF NOT EXISTS idx_user_consent_revoked_at ON user_consent (revoked_at);
CREATE INDEX IF NOT EXISTS idx_user_consent_scopes_gin ON user_consent USING GIN (granted_scopes);

-- 7. MFA & Trusted Devices
CREATE TABLE IF NOT EXISTS trusted_device (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  client_id_text TEXT,
  device_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_trusted_device_user ON trusted_device(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_trusted_device_user_hash ON trusted_device(user_id, device_hash);

CREATE TABLE IF NOT EXISTS user_mfa_totp (
  user_id UUID PRIMARY KEY REFERENCES app_user(id) ON DELETE CASCADE,
  secret_encrypted TEXT NOT NULL,
  confirmed_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS mfa_recovery_code (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, code_hash)
);

-- 8. Schema Migrations
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMIT;
