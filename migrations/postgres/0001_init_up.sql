BEGIN;
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- (Opcional compat) Tenants/Clients para tooling antiguo o inspección; NO usados por data-plane
CREATE TABLE IF NOT EXISTS tenant (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL, slug TEXT UNIQUE NOT NULL,
  settings JSONB DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS client (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,  -- sin FK a tenant, a propósito
  name TEXT NOT NULL, client_id TEXT UNIQUE NOT NULL,
  client_type TEXT NOT NULL CHECK (client_type IN ('public','confidential')),
  redirect_uris TEXT[] NOT NULL DEFAULT '{}',
  allowed_origins TEXT[] NOT NULL DEFAULT '{}',
  providers TEXT[] NOT NULL DEFAULT '{}',
  scopes TEXT[] NOT NULL DEFAULT '{}',
  active_version_id UUID, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS client_version (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id UUID NOT NULL, -- sin FK dura
  version TEXT NOT NULL,
  claim_schema_json JSONB NOT NULL,
  claim_mapping_json JSONB NOT NULL,
  crypto_config_json JSONB NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('draft','active','retired')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  promoted_at TIMESTAMPTZ
);

-- Users / Identities
CREATE TABLE IF NOT EXISTS app_user (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,          -- sin FK (FS es la fuente de verdad)
  email TEXT NOT NULL,
  email_verified BOOLEAN NOT NULL DEFAULT false,
  status TEXT NOT NULL DEFAULT 'active',
  metadata JSONB NOT NULL DEFAULT '{}',
  disabled_at TIMESTAMPTZ, disabled_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, email)
);
CREATE TABLE IF NOT EXISTS identity (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider IN ('password','google','facebook')),
  provider_user_id TEXT,
  email TEXT, email_verified BOOLEAN,
  password_hash TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_identity_user ON identity(user_id);
CREATE INDEX IF NOT EXISTS idx_identity_provider_uid ON identity(provider, provider_user_id);
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='ux_identity_user_provider') THEN
    ALTER TABLE identity ADD CONSTRAINT ux_identity_user_provider UNIQUE (user_id, provider);
  END IF;
END$$;

-- Refresh tokens (data-plane cortado)
CREATE TABLE IF NOT EXISTS refresh_token (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,
  user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  client_id_text TEXT NOT NULL,       -- << clave textual
  token_hash TEXT NOT NULL UNIQUE,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  rotated_from UUID NULL REFERENCES refresh_token(id) ON DELETE SET NULL,
  revoked_at TIMESTAMPTZ NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_token_tenant_user_client
  ON refresh_token (tenant_id, user_id, client_id_text);
CREATE INDEX IF NOT EXISTS idx_refresh_token_revoked_at ON refresh_token (revoked_at);
CREATE INDEX IF NOT EXISTS idx_refresh_token_expires_at ON refresh_token (expires_at) WHERE revoked_at IS NULL;

-- Email flows
CREATE TABLE IF NOT EXISTS email_verification_token (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL, user_id UUID NOT NULL,
  token_hash BYTEA NOT NULL UNIQUE,
  sent_to TEXT NOT NULL, ip INET, user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_email_verif_token_expires_at ON email_verification_token (expires_at);
CREATE INDEX IF NOT EXISTS idx_email_verif_token_tenant_user ON email_verification_token (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS password_reset_token (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL, user_id UUID NOT NULL,
  token_hash BYTEA NOT NULL UNIQUE,
  sent_to TEXT NOT NULL, ip INET, user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_pwd_reset_token_expires_at ON password_reset_token (expires_at);
CREATE INDEX IF NOT EXISTS idx_pwd_reset_token_tenant_user ON password_reset_token (tenant_id, user_id);

-- Scopes + Consents (consents cortado a client_id_text)
CREATE TABLE IF NOT EXISTS scope (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS idx_scope_tenant_name ON scope(tenant_id, name);

CREATE TABLE IF NOT EXISTS user_consent (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,
  user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  client_id_text TEXT NOT NULL,
  granted_scopes TEXT[] NOT NULL,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);
DO $$
BEGIN
  IF NOT EXISTS (
     SELECT 1 FROM pg_constraint
      WHERE conrelid='user_consent'::regclass AND contype='u'
        AND pg_get_constraintdef(oid) ILIKE '%(tenant_id, user_id, client_id_text)%'
  ) THEN
    ALTER TABLE user_consent
      ADD CONSTRAINT ux_user_consent_tenant_user_client UNIQUE (tenant_id, user_id, client_id_text);
  END IF;
END$$;
CREATE INDEX IF NOT EXISTS idx_user_consent_tenant_user_client
  ON user_consent (tenant_id, user_id, client_id_text);
CREATE INDEX IF NOT EXISTS idx_user_consent_revoked_at ON user_consent (revoked_at);
CREATE INDEX IF NOT EXISTS idx_user_consent_scopes_gin ON user_consent USING GIN (granted_scopes);

-- Trusted devices / MFA
CREATE TABLE IF NOT EXISTS trusted_device (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID NOT NULL,
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
  confirmed_at TIMESTAMPTZ, last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE OR REPLACE FUNCTION trg_user_mfa_totp_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END; $$ LANGUAGE plpgsql;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='user_mfa_totp_updated_at') THEN
    CREATE TRIGGER user_mfa_totp_updated_at
    BEFORE UPDATE ON user_mfa_totp
    FOR EACH ROW EXECUTE FUNCTION trg_user_mfa_totp_updated_at();
  END IF;
END$$;

CREATE TABLE IF NOT EXISTS mfa_recovery_code (
  id BIGSERIAL PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, code_hash)
);

-- RBAC
CREATE TABLE IF NOT EXISTS rbac_role (
  tenant_id UUID NOT NULL, role TEXT NOT NULL, description TEXT,
  PRIMARY KEY (tenant_id, role)
);
CREATE TABLE IF NOT EXISTS rbac_perm (
  tenant_id UUID NOT NULL, perm TEXT NOT NULL, description TEXT,
  PRIMARY KEY (tenant_id, perm)
);
CREATE TABLE IF NOT EXISTS rbac_role_perm (
  tenant_id UUID NOT NULL, role TEXT NOT NULL, perm TEXT NOT NULL,
  PRIMARY KEY (tenant_id, role, perm)
);
CREATE INDEX IF NOT EXISTS idx_rbac_role_perm_perm ON rbac_role_perm(tenant_id, perm);

CREATE TABLE IF NOT EXISTS rbac_user_role (
  tenant_id UUID NOT NULL, user_id UUID NOT NULL, role TEXT NOT NULL,
  PRIMARY KEY (tenant_id, user_id, role)
);
CREATE INDEX IF NOT EXISTS idx_rbac_user_role_user ON rbac_user_role(user_id);

-- (Opcional) signing_keys si querés usar DB para llaves globales en escenarios 2/3
CREATE TABLE IF NOT EXISTS signing_keys (
  kid TEXT PRIMARY KEY,
  alg TEXT NOT NULL CHECK (alg = 'EdDSA'),
  public_key BYTEA NOT NULL,
  private_key BYTEA,
  status TEXT NOT NULL CHECK (status IN ('active','retiring','retired')),
  not_before TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  rotated_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_signing_keys_active ON signing_keys(status) WHERE status='active';
CREATE INDEX IF NOT EXISTS ix_signing_keys_status ON signing_keys(status);
CREATE INDEX IF NOT EXISTS ix_signing_keys_not_before ON signing_keys(not_before);

COMMIT;
