package commands

import (
	"fmt"
	"os"
	"strings"

	cfgpkg "github.com/dropDatabas3/hellojohn/cmd/hjctl/cfg"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// paginationQuery builds a URL query string fragment from page/limit values.
// Callers append this to list endpoint paths:
//
//	c.Get(ctx, "/v2/admin/tenants"+paginationQuery(page, limit), &result)
func paginationQuery(page, limit int) string {
	if page <= 0 && limit <= 0 {
		return ""
	}
	q := "?"
	if page > 0 {
		q += fmt.Sprintf("page=%d", page)
	}
	if limit > 0 {
		if q != "?" {
			q += "&"
		}
		q += fmt.Sprintf("limit=%d", limit)
	}
	return q
}

// addPaginationFlags adds --page and --limit flags to a list command.
func addPaginationFlags(cmd *cobra.Command, page, limit *int) {
	cmd.Flags().IntVar(page, "page", 0, "Page number for pagination (1-based; 0 = server default)")
	cmd.Flags().IntVar(limit, "limit", 0, "Max items per page (0 = server default)")
}

func splitAndTrim(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// loadCLIConfig reads the CLI config using the canonical cfg package.
func loadCLIConfig() (cfgpkg.Config, error) {
	return cfgpkg.Load()
}

// saveCLIConfig writes the CLI config using the canonical cfg package.
func saveCLIConfig(c cfgpkg.Config) error {
	return cfgpkg.Save(c)
}

func setConfigValue(key, value string) error {
	key = strings.ReplaceAll(key, "-", "_")
	c, err := loadCLIConfig()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	switch key {
	case "base_url":
		c.BaseURL = value
	case "api_key":
		fmt.Fprintln(os.Stderr, "[WARN] Storing API key in config file. Use HELLOJOHN_API_KEY env var for better security - command line args expose keys in shell history.")
		c.APIKey = value
	case "default_tenant":
		c.DefaultTenant = value
	case "output":
		c.Output = value
	default:
		return fmt.Errorf("unknown config key: %s (valid: base_url, api_key, default_tenant, output)", key)
	}
	if err := saveCLIConfig(c); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Config key '%s' set.\n", key)
	return nil
}

// maskAPIKey replaces all but the first 6 and last 4 characters of an API key
// with "****" to prevent accidental exposure in terminal output.
func maskAPIKey(key string) string {
	if len(key) <= 10 {
		return "****"
	}
	return key[:6] + "****" + key[len(key)-4:]
}

func getConfigValue(key string) error {
	key = strings.ReplaceAll(key, "-", "_")
	c, err := loadCLIConfig()
	if err != nil {
		return err
	}
	var val string
	switch key {
	case "base_url":
		val = c.BaseURL
	case "api_key":
		// CLI-3: mask API key to prevent plaintext exposure via `config get api_key`.
		val = maskAPIKey(c.APIKey)
	case "default_tenant":
		val = c.DefaultTenant
	case "output":
		val = c.Output
	default:
		return fmt.Errorf("unknown config key: %s", key)
	}
	fmt.Println(val)
	return nil
}

func showConfig() error {
	c, err := loadCLIConfig()
	if err != nil {
		return err
	}
	// CLI-3: mask the API key before printing to avoid plaintext exposure.
	display := c
	if display.APIKey != "" {
		display.APIKey = maskAPIKey(display.APIKey)
	}
	out := cfgpkg.Config{
		BaseURL:       display.BaseURL,
		APIKey:        display.APIKey,
		DefaultTenant: display.DefaultTenant,
		Output:        display.Output,
	}
	data, err := yaml.Marshal(&out)
	if err != nil {
		return fmt.Errorf("config: marshal yaml: %w", err)
	}
	os.Stdout.Write(data)
	return nil
}
