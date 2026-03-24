-- Down migration: drops all control plane tables in reverse FK order

DROP TABLE IF EXISTS system_settings;
DROP TABLE IF EXISTS cp_admin_refresh_token;
DROP TABLE IF EXISTS cp_admin;
DROP TABLE IF EXISTS cp_claims_config;
DROP TABLE IF EXISTS cp_scope;
DROP TABLE IF EXISTS cp_client;
DROP TABLE IF EXISTS cp_tenant;
