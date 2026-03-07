-- password_history: almacena hashes previos para prevenir reutilización.
-- EPIC 001, Fase 1.3
CREATE TABLE IF NOT EXISTS password_history (
    id          CHAR(36) DEFAULT (UUID()) PRIMARY KEY,
    user_id     CHAR(36) NOT NULL,
    hash        TEXT NOT NULL,
    algorithm   VARCHAR(20) NOT NULL DEFAULT 'argon2id',
    created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE,
    INDEX idx_password_history_user (user_id)
);
