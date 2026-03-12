package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const systemEmailProviderKey = "email_provider"

type pgSystemSettingsRepo struct {
	pool *pgxpool.Pool
}

func (r *pgSystemSettingsRepo) GetEmailProvider(ctx context.Context) (*repository.GlobalEmailProviderSettings, error) {
	const query = `SELECT value FROM system_settings WHERE key = $1`

	var raw []byte
	err := r.pool.QueryRow(ctx, query, systemEmailProviderKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pg: get system email provider: %w", err)
	}

	var out repository.GlobalEmailProviderSettings
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("pg: unmarshal system email provider: %w", err)
	}
	return &out, nil
}

func (r *pgSystemSettingsRepo) SetEmailProvider(ctx context.Context, settings repository.GlobalEmailProviderSettings, actor string) error {
	const query = `
		INSERT INTO system_settings (key, value, updated_at, updated_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (key) DO UPDATE SET
			value = EXCLUDED.value,
			updated_at = EXCLUDED.updated_at,
			updated_by = EXCLUDED.updated_by`

	settings.UpdatedAt = time.Now().UTC()
	settings.UpdatedBy = actor

	raw, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("pg: marshal system email provider: %w", err)
	}

	if _, err := r.pool.Exec(ctx, query, systemEmailProviderKey, raw, settings.UpdatedAt, actor); err != nil {
		return fmt.Errorf("pg: set system email provider: %w", err)
	}
	return nil
}

func (r *pgSystemSettingsRepo) DeleteEmailProvider(ctx context.Context) error {
	const query = `DELETE FROM system_settings WHERE key = $1`
	if _, err := r.pool.Exec(ctx, query, systemEmailProviderKey); err != nil {
		return fmt.Errorf("pg: delete system email provider: %w", err)
	}
	return nil
}

var _ repository.SystemSettingsRepository = (*pgSystemSettingsRepo)(nil)
