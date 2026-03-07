// Package cfg provides the shared configuration struct and I/O helpers for hjctl.
// Both the main package (root.go) and the commands package (config_helpers.go)
// import this package to avoid duplicating config struct definitions.
package cfg

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the CLI configuration stored at ~/.hjctl/config.yaml.
type Config struct {
	BaseURL       string `yaml:"base_url,omitempty"`
	APIKey        string `yaml:"api_key,omitempty"`
	DefaultTenant string `yaml:"default_tenant,omitempty"`
	Output        string `yaml:"output,omitempty"`
}

// Dir returns the path to ~/.hjctl/
func Dir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".hjctl")
}

// Path returns the path to ~/.hjctl/config.yaml
func Path() string {
	dir := Dir()
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "config.yaml")
}

// Load reads the config file. Returns zero Config if not found.
func Load() (Config, error) {
	var c Config
	p := Path()
	if p == "" {
		return c, nil
	}

	data, err := os.ReadFile(p)
	if err != nil {
		return c, nil // file not found is fine
	}

	if err := yaml.Unmarshal(data, &c); err != nil {
		return c, err
	}
	return c, nil
}

// Save writes the config file with 0600 permissions.
func Save(c Config) error {
	dir := Dir()
	if dir == "" {
		return os.ErrNotExist
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := yaml.Marshal(&c)
	if err != nil {
		return err
	}

	return os.WriteFile(Path(), data, 0600)
}
