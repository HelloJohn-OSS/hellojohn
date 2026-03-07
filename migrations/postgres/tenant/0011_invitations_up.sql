-- Phase 10C: user invitations
CREATE TABLE IF NOT EXISTS user_invitation (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL,
    email        TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    status       TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','accepted','expired','revoked')),
    invited_by   UUID NOT NULL REFERENCES app_user(id) ON DELETE RESTRICT,
    roles        TEXT[] NOT NULL DEFAULT '{}',
    expires_at   TIMESTAMPTZ NOT NULL,
    accepted_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_inv_tenant_status ON user_invitation (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_inv_token_hash ON user_invitation (token_hash);

