-- password_history: almacena hashes previos para prevenir reutilización.
-- EPIC 001, Fase 1.3
CREATE TABLE IF NOT EXISTS password_history (
    id          UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    hash        TEXT NOT NULL,
    algorithm   TEXT NOT NULL DEFAULT 'argon2id',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_password_history_user ON password_history(user_id);
