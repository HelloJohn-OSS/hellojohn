package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

const mysqlSystemEmailProviderKey = "email_provider"

type mysqlSystemSettingsRepo struct {
	db *sql.DB
}

func (r *mysqlSystemSettingsRepo) GetEmailProvider(ctx context.Context) (*repository.GlobalEmailProviderSettings, error) {
	const query = `SELECT value FROM system_settings WHERE ` + "`key` = ? LIMIT 1"

	var raw []byte
	err := r.db.QueryRowContext(ctx, query, mysqlSystemEmailProviderKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("mysql: get system email provider: %w", err)
	}

	var out repository.GlobalEmailProviderSettings
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("mysql: unmarshal system email provider: %w", err)
	}
	return &out, nil
}

func (r *mysqlSystemSettingsRepo) SetEmailProvider(ctx context.Context, settings repository.GlobalEmailProviderSettings, actor string) error {
	const query = `
		INSERT INTO system_settings (` + "`key`" + `, value, updated_at, updated_by)
		VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			value = VALUES(value),
			updated_at = VALUES(updated_at),
			updated_by = VALUES(updated_by)`

	settings.UpdatedAt = time.Now().UTC()
	settings.UpdatedBy = actor

	raw, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("mysql: marshal system email provider: %w", err)
	}

	if _, err := r.db.ExecContext(ctx, query, mysqlSystemEmailProviderKey, raw, settings.UpdatedAt, actor); err != nil {
		return fmt.Errorf("mysql: set system email provider: %w", err)
	}
	return nil
}

func (r *mysqlSystemSettingsRepo) DeleteEmailProvider(ctx context.Context) error {
	const query = `DELETE FROM system_settings WHERE ` + "`key` = ?"
	if _, err := r.db.ExecContext(ctx, query, mysqlSystemEmailProviderKey); err != nil {
		return fmt.Errorf("mysql: delete system email provider: %w", err)
	}
	return nil
}

var _ repository.SystemSettingsRepository = (*mysqlSystemSettingsRepo)(nil)
