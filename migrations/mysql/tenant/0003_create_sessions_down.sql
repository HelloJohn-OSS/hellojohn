-- Rollback: Drop sessions table (MySQL)
DROP TABLE IF EXISTS sessions;

DELETE FROM schema_migrations WHERE version = '0003_create_sessions';
