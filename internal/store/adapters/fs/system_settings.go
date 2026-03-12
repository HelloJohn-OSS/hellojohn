package fs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"gopkg.in/yaml.v3"
)

type fsSystemSettingsRepo struct {
	conn *fsConnection
}

var _ repository.SystemSettingsRepository = (*fsSystemSettingsRepo)(nil)

func (r *fsSystemSettingsRepo) filePath() string {
	return filepath.Join(r.conn.root, "system", "email_provider.yaml")
}

func (r *fsSystemSettingsRepo) GetEmailProvider(ctx context.Context) (*repository.GlobalEmailProviderSettings, error) {
	_ = ctx

	r.conn.mu.RLock()
	defer r.conn.mu.RUnlock()

	data, err := os.ReadFile(r.filePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("fs: read global email provider: %w", err)
	}

	var s repository.GlobalEmailProviderSettings
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("fs: parse global email provider: %w", err)
	}
	return &s, nil
}

func (r *fsSystemSettingsRepo) SetEmailProvider(ctx context.Context, settings repository.GlobalEmailProviderSettings, actor string) error {
	_ = ctx

	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	dir := filepath.Dir(r.filePath())
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("fs: create system dir: %w", err)
	}

	settings.UpdatedAt = time.Now().UTC()
	settings.UpdatedBy = actor

	data, err := yaml.Marshal(settings)
	if err != nil {
		return fmt.Errorf("fs: marshal global email provider: %w", err)
	}

	if err := os.WriteFile(r.filePath(), data, 0600); err != nil {
		return fmt.Errorf("fs: write global email provider: %w", err)
	}
	return nil
}

func (r *fsSystemSettingsRepo) DeleteEmailProvider(ctx context.Context) error {
	_ = ctx

	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	if err := os.Remove(r.filePath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("fs: delete global email provider: %w", err)
	}
	return nil
}
