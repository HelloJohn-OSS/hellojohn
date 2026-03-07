-- migrations/mysql/global/0001_control_plane_down.sql
-- Rollback del 0001_control_plane_up.sql
-- IMPORTANTE: DROP en orden inverso al de FK (hijos antes que padres).

DROP TABLE IF EXISTS cp_admin_refresh_token;
DROP TABLE IF EXISTS cp_admin;
DROP TABLE IF EXISTS cp_claims_config;
DROP TABLE IF EXISTS cp_scope;
DROP TABLE IF EXISTS cp_client;
DROP TABLE IF EXISTS cp_tenant;
