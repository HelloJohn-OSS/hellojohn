BEGIN;

ALTER TABLE IF EXISTS trusted_device RENAME TO mfa_trusted_device;
ALTER INDEX IF EXISTS ix_trusted_device_user RENAME TO ix_mfa_trusted_device_user;
ALTER INDEX IF EXISTS ux_trusted_device_user_hash RENAME TO ux_mfa_trusted_device_user_hash;

ALTER TABLE IF EXISTS user_mfa_totp RENAME TO mfa_totp;

COMMIT;
