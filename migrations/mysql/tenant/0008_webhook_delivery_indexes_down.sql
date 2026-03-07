-- Rollback de Phase 5.8
ALTER TABLE webhook_delivery
    DROP INDEX idx_wd_admin_event,
    DROP INDEX idx_wd_admin_status,
    DROP INDEX idx_wd_admin_list;
