-- Down migration: drops all tenant tables
BEGIN;
DROP TABLE IF EXISTS schema_migrations;
DROP TABLE IF EXISTS mfa_recovery_code;
DROP TABLE IF EXISTS user_mfa_totp;
DROP TABLE IF EXISTS trusted_device;
DROP TABLE IF EXISTS user_consent;
DROP TABLE IF EXISTS password_reset_token;
DROP TABLE IF EXISTS email_verification_token;
DROP TABLE IF EXISTS rbac_user_role;
DROP TABLE IF EXISTS rbac_role;
DROP TABLE IF EXISTS refresh_token;
DROP TABLE IF EXISTS identity;
DROP TABLE IF EXISTS app_user;
COMMIT;
