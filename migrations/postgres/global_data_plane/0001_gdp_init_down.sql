-- migrations/postgres/global_data_plane/0001_gdp_init_down.sql
-- Rollback: drop all GDP tables in FK-safe order.

BEGIN;
DROP TABLE IF EXISTS password_history CASCADE;
DROP TABLE IF EXISTS webauthn_credential CASCADE;
DROP TABLE IF EXISTS invitation CASCADE;
DROP TABLE IF EXISTS webhook_delivery CASCADE;
DROP TABLE IF EXISTS webhook CASCADE;
DROP TABLE IF EXISTS audit_log CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;
DROP TABLE IF EXISTS user_consent CASCADE;
DROP TABLE IF EXISTS mfa_trusted_device CASCADE;
DROP TABLE IF EXISTS mfa_recovery_code CASCADE;
DROP TABLE IF EXISTS mfa_totp CASCADE;
DROP TABLE IF EXISTS password_reset_token CASCADE;
DROP TABLE IF EXISTS email_verification_token CASCADE;
DROP TABLE IF EXISTS rbac_user_role CASCADE;
DROP TABLE IF EXISTS rbac_role CASCADE;
DROP TABLE IF EXISTS refresh_token CASCADE;
DROP TABLE IF EXISTS identity CASCADE;
DROP TABLE IF EXISTS app_user CASCADE;
DROP TABLE IF EXISTS _migrations CASCADE;
COMMIT;
