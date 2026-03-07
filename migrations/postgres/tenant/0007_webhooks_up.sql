CREATE TABLE IF NOT EXISTS webhook_delivery (
    id             UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    webhook_id     TEXT NOT NULL,
    event_type     TEXT NOT NULL,
    payload        JSONB NOT NULL,
    status         TEXT NOT NULL DEFAULT 'pending',
    attempts       INT NOT NULL DEFAULT 0,
    last_attempt   TIMESTAMPTZ,
    next_retry     TIMESTAMPTZ,
    http_status    INT,
    response_body  TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Índices Parciales (B-Tree) vitales para evitar Full Scans del Worker 
CREATE INDEX idx_webhook_delivery_status ON webhook_delivery(status) WHERE status IN ('pending', 'failed');
CREATE INDEX idx_webhook_delivery_next ON webhook_delivery(next_retry) WHERE status IN ('pending', 'failed');
