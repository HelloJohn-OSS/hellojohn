BEGIN;
DROP TABLE IF EXISTS rbac_user_role;
DROP TABLE IF EXISTS rbac_role_perm;
DROP TABLE IF EXISTS rbac_perm;
DROP TABLE IF EXISTS rbac_role;

DROP TABLE IF EXISTS mfa_recovery_code;
DROP TRIGGER IF EXISTS user_mfa_totp_updated_at ON user_mfa_totp;
DROP FUNCTION IF EXISTS trg_user_mfa_totp_updated_at;
DROP TABLE IF EXISTS user_mfa_totp;

DROP TABLE IF EXISTS trusted_device;
DROP INDEX IF EXISTS idx_user_consent_scopes_gin;
DROP TABLE IF EXISTS user_consent;
DROP TABLE IF EXISTS scope;

DROP TABLE IF EXISTS password_reset_token;
DROP TABLE IF EXISTS email_verification_token;

DROP TABLE IF EXISTS refresh_token;
DROP TABLE IF EXISTS identity;
DROP TABLE IF EXISTS app_user;

DROP TABLE IF EXISTS client_version;
DROP TABLE IF EXISTS client;
DROP TABLE IF EXISTS tenant;

DROP TABLE IF EXISTS signing_keys;
COMMIT;
