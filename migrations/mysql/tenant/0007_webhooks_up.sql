CREATE TABLE IF NOT EXISTS webhook_delivery (
    id             CHAR(36) DEFAULT (UUID()) PRIMARY KEY,
    webhook_id     VARCHAR(255) NOT NULL,
    event_type     VARCHAR(100) NOT NULL,
    payload        JSON NOT NULL,
    status         VARCHAR(50) NOT NULL DEFAULT 'pending',
    attempts       INT NOT NULL DEFAULT 0,
    last_attempt   DATETIME(6),
    next_retry     DATETIME(6),
    http_status    INT,
    response_body  TEXT,
    created_at     DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX idx_webhook_delivery_status (status),
    INDEX idx_webhook_delivery_next (next_retry)
);
