-- Rollback de Phase 5.8: eliminar indices admin
DROP INDEX CONCURRENTLY IF EXISTS idx_wd_admin_event;
DROP INDEX CONCURRENTLY IF EXISTS idx_wd_admin_status;
DROP INDEX CONCURRENTLY IF EXISTS idx_wd_admin_list;
