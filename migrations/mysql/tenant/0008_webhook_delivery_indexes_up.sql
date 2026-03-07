-- Phase 5.8: indices para queries admin en webhook_delivery (MySQL)
-- MySQL no soporta CONCURRENTLY, pero si indices compuestos con columnas de ordenamiento.
-- IMPORTANT: en MySQL 8.0+ los indices compuestos soportan ASC/DESC por columna.

ALTER TABLE webhook_delivery
    ADD INDEX idx_wd_admin_list (webhook_id, created_at DESC),
    ADD INDEX idx_wd_admin_status (webhook_id, status, created_at DESC),
    ADD INDEX idx_wd_admin_event (webhook_id, event_type, created_at DESC);
