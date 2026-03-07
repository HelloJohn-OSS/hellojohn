-- MySQL inicial (simplificado)
CREATE TABLE IF NOT EXISTS tenant (
  id CHAR(36) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  slug VARCHAR(255) NOT NULL UNIQUE,
  settings JSON,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS client (
  id CHAR(36) PRIMARY KEY,
  tenant_id CHAR(36) NOT NULL,
  name VARCHAR(255) NOT NULL,
  client_id VARCHAR(255) NOT NULL UNIQUE,
  client_type ENUM('public','confidential') NOT NULL,
  redirect_uris JSON NOT NULL,
  allowed_origins JSON NOT NULL,
  providers JSON NOT NULL,
  scopes JSON NOT NULL,
  active_version_id CHAR(36) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_client_tenant FOREIGN KEY (tenant_id) REFERENCES tenant(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS client_version (
  id CHAR(36) PRIMARY KEY,
  client_id CHAR(36) NOT NULL,
  version VARCHAR(64) NOT NULL,
  claim_schema_json JSON NOT NULL,
  claim_mapping_json JSON NOT NULL,
  crypto_config_json JSON NOT NULL,
  status ENUM('draft','active','retired') NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  promoted_at TIMESTAMP NULL,
  CONSTRAINT fk_cv_client FOREIGN KEY (client_id) REFERENCES client(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS app_user (
  id CHAR(36) PRIMARY KEY,
  tenant_id CHAR(36) NOT NULL,
  email VARCHAR(320) NOT NULL,
  email_verified BOOLEAN NOT NULL DEFAULT 0,
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  metadata JSON NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_tenant_email (tenant_id, email),
  CONSTRAINT fk_user_tenant FOREIGN KEY (tenant_id) REFERENCES tenant(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS identity (
  id CHAR(36) PRIMARY KEY,
  user_id CHAR(36) NOT NULL,
  provider ENUM('password','google','facebook') NOT NULL,
  provider_user_id VARCHAR(255),
  email VARCHAR(320),
  email_verified BOOLEAN,
  password_hash TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_identity_user FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE,
  KEY idx_identity_user (user_id),
  KEY idx_identity_provider_uid (provider, provider_user_id)
);
