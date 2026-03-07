-- Migración: Crear tabla sessions para tracking de sesiones activas
-- Permite administrar, listar y revocar sesiones desde el panel admin

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    session_id_hash TEXT NOT NULL UNIQUE,

    -- Metadata de cliente
    ip_address INET,
    user_agent TEXT,
    device_type VARCHAR(20),
    browser VARCHAR(100),
    os VARCHAR(100),

    -- Geolocalización
    country_code CHAR(2),
    country VARCHAR(100),
    city VARCHAR(100),

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by UUID,
    revoke_reason TEXT
);

-- Índices para consultas frecuentes
CREATE INDEX idx_sessions_user ON sessions(user_id, created_at DESC);
CREATE INDEX idx_sessions_hash ON sessions(session_id_hash);
CREATE INDEX idx_sessions_expires ON sessions(expires_at) WHERE revoked_at IS NULL;
CREATE INDEX idx_sessions_status ON sessions(revoked_at, expires_at);

COMMENT ON TABLE sessions IS 'Sesiones activas de usuarios para tracking y administración';
COMMENT ON COLUMN sessions.session_id_hash IS 'SHA256 del session token para búsqueda segura';
COMMENT ON COLUMN sessions.device_type IS 'desktop, mobile, tablet, unknown';
