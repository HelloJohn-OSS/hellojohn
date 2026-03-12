CREATE TABLE IF NOT EXISTS system_settings (
    key        TEXT        NOT NULL PRIMARY KEY,
    value      JSONB       NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by TEXT        NOT NULL DEFAULT ''
);

COMMENT ON TABLE system_settings IS 'Global key-value settings for control plane. Key email_provider stores encrypted GlobalEmailProviderSettings.';
