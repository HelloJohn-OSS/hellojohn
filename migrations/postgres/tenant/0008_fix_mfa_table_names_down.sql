BEGIN;

ALTER TABLE IF EXISTS mfa_trusted_device RENAME TO trusted_device;
ALTER INDEX IF EXISTS ix_mfa_trusted_device_user RENAME TO ix_trusted_device_user;
ALTER INDEX IF EXISTS ux_mfa_trusted_device_user_hash RENAME TO ux_trusted_device_user_hash;

ALTER TABLE IF EXISTS mfa_totp RENAME TO user_mfa_totp;

COMMIT;
