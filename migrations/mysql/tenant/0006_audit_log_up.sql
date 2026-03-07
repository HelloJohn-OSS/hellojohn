-- 0006_audit_log_up.sql
-- EPIC 004: Audit Logs - persistent audit trail per tenant

CREATE TABLE IF NOT EXISTS audit_log (
    id          CHAR(36) DEFAULT (UUID()) PRIMARY KEY,
    event_type  VARCHAR(100) NOT NULL,
    actor_id    VARCHAR(255),
    actor_type  VARCHAR(20) NOT NULL DEFAULT 'system',
    target_id   VARCHAR(255),
    target_type VARCHAR(50),
    ip_address  VARCHAR(45),
    user_agent  TEXT,
    metadata    JSON DEFAULT (JSON_OBJECT()),
    result      VARCHAR(20) NOT NULL DEFAULT 'success',
    created_at  DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_audit_log_type (event_type),
    INDEX idx_audit_log_actor (actor_id),
    INDEX idx_audit_log_target (target_id),
    INDEX idx_audit_log_created (created_at DESC),
    INDEX idx_audit_log_type_created (event_type, created_at DESC)
);
