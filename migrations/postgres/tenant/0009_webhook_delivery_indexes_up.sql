-- Phase 5.8: indices para queries admin en webhook_delivery
-- Estos indices cubren los patrones de acceso del panel de administracion:
--   - Historial por webhook ordenado por fecha
--   - Historial filtrado por status + fecha
--   - Historial filtrado por event_type + fecha
-- Los indices del worker (status + next_retry) definidos en 0007 no se modifican.

-- Indice principal para listado ordenado por fecha (caso mas frecuente)
CREATE INDEX IF NOT EXISTS idx_wd_admin_list
    ON webhook_delivery (webhook_id, created_at DESC);

-- Indice para filtro por status + fecha
CREATE INDEX IF NOT EXISTS idx_wd_admin_status
    ON webhook_delivery (webhook_id, status, created_at DESC);

-- Indice para filtro por event_type + fecha
CREATE INDEX IF NOT EXISTS idx_wd_admin_event
    ON webhook_delivery (webhook_id, event_type, created_at DESC);
