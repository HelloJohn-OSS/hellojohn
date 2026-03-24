-- Down migration: drops all tenant tables in reverse FK order
BEGIN;

DROP TABLE IF EXISTS schema_migrations;
DROP TABLE IF EXISTS user_invitation;
DROP TABLE IF EXISTS webauthn_credential;
DROP TABLE IF EXISTS webhook_delivery;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS password_history;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS mfa_recovery_code;
DROP TABLE IF EXISTS mfa_totp;
DROP TABLE IF EXISTS mfa_trusted_device;
DROP TABLE IF EXISTS scope;
DROP TABLE IF EXISTS user_consent;
DROP TABLE IF EXISTS password_reset_token;
DROP TABLE IF EXISTS email_verification_token;
DROP TABLE IF EXISTS rbac_user_role;
DROP TABLE IF EXISTS rbac_role;
DROP TABLE IF EXISTS refresh_token;
DROP TABLE IF EXISTS identity;
DROP TABLE IF EXISTS app_user;

COMMIT;
