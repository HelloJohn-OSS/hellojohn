package main

import (
	"fmt"
	"os"

	"github.com/dropDatabas3/hellojohn/cmd/hjctl/client"
	"github.com/dropDatabas3/hellojohn/cmd/hjctl/commands"
	"github.com/spf13/cobra"
)

const version = "0.1.0"

var (
	flagBaseURL string
	flagAPIKey  string
	flagOutput  string
	flagTimeout int
	flagTenant  string
)

var rootCmd = &cobra.Command{
	Use:   "hjctl",
	Short: "HelloJohn CLI — manage your auth platform from the terminal",
	Long: `hjctl is the official CLI for HelloJohn, a self-hosted multi-tenant
authentication and identity platform. Use it to manage tenants, users,
clients, API keys, and more.

Configuration precedence:
  1. Command-line flags (highest)
  2. Environment variables (HELLOJOHN_*)
  3. Config file ~/.hjctl/config.yaml (lowest)`,
	SilenceUsage:  true,
	SilenceErrors: true,
	Version:       version,
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&flagBaseURL, "base-url", "", "HelloJohn server URL (env: HELLOJOHN_BASE_URL)")
	rootCmd.PersistentFlags().StringVar(&flagAPIKey, "api-key", "", "API key (deprecated: use HELLOJOHN_API_KEY env var - passing via flag exposes key in process list)")
	_ = rootCmd.PersistentFlags().MarkHidden("api-key") // Hide from help to discourage use; still functional
	rootCmd.PersistentFlags().StringVarP(&flagOutput, "output", "o", "json", "Output format: json, table, yaml (env: HELLOJOHN_OUTPUT)")
	rootCmd.PersistentFlags().IntVar(&flagTimeout, "timeout", 30, "HTTP timeout in seconds")
	rootCmd.PersistentFlags().StringVarP(&flagTenant, "tenant", "t", "", "Default tenant slug (env: HELLOJOHN_DEFAULT_TENANT)")

	// Helper closures for dependency injection into commands
	getClient := func() (*client.Client, error) {
		baseURL, err := requireBaseURL()
		if err != nil {
			return nil, err
		}
		apiKey, err := requireAPIKey()
		if err != nil {
			return nil, err
		}
		return client.New(baseURL, apiKey, flagTimeout), nil
	}
	outputFmt := func() string { return flagOutput }
	getTenant := func() (string, error) { return requireTenant() }

	saveCfg := func(baseURL, apiKey string) error {
		cfg, err := loadConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] config parse error: %v\n", err)
		}
		if baseURL != "" {
			cfg.BaseURL = baseURL
		}
		if apiKey != "" {
			cfg.APIKey = apiKey
		}
		if baseURL == "" && apiKey == "" {
			cfg.APIKey = "" // logout clears key
		}
		return saveConfig(cfg)
	}

	// Register all command groups
	rootCmd.AddCommand(commands.NewAuthCmd(
		func() string { return flagBaseURL },
		func() string { return flagAPIKey },
		func() int { return flagTimeout },
		saveCfg,
	))
	rootCmd.AddCommand(commands.NewConfigCmd())
	rootCmd.AddCommand(commands.NewAPIKeyCmd(getClient, outputFmt))
	rootCmd.AddCommand(commands.NewTenantCmd(getClient, outputFmt))
	rootCmd.AddCommand(commands.NewUserCmd(getClient, outputFmt, getTenant))
	rootCmd.AddCommand(commands.NewClientCmd(getClient, outputFmt, getTenant))
	rootCmd.AddCommand(commands.NewScopeCmd(getClient, outputFmt, getTenant))
	rootCmd.AddCommand(commands.NewRoleCmd(getClient, outputFmt, getTenant))
	rootCmd.AddCommand(commands.NewKeyCmd(getClient, outputFmt, getTenant))
	rootCmd.AddCommand(commands.NewAuditCmd(getClient, outputFmt, getTenant))
	getBaseURL := func() (string, error) { return requireBaseURL() }
	rootCmd.AddCommand(commands.NewSystemCmd(getClient, outputFmt, getBaseURL, func() int { return flagTimeout }))
	rootCmd.AddCommand(commands.NewProviderCmd())
	rootCmd.AddCommand(commands.NewMailCmd(getClient, outputFmt))
	rootCmd.AddCommand(commands.NewOIDCCmd())
	rootCmd.AddCommand(commands.NewWebhookCmd(getClient, outputFmt, getTenant))
	rootCmd.AddCommand(commands.NewSessionCmd(getClient, outputFmt, getTenant))
	rootCmd.AddCommand(commands.NewMFACmd(getClient, outputFmt, getTenant))
	rootCmd.AddCommand(commands.NewClaimCmd(getClient, outputFmt, getTenant))
	rootCmd.AddCommand(commands.NewTokenCmd(getClient, outputFmt, getTenant))
	rootCmd.AddCommand(commands.NewConsentCmd(getClient, outputFmt, getTenant))
	rootCmd.AddCommand(commands.NewInvitationCmd(getClient, outputFmt, getTenant))
	rootCmd.AddCommand(commands.NewMigrateCmd(getClient, outputFmt))

	// MCP server command — uses raw base URL/API key getters (not Client)
	rootCmd.AddCommand(commands.NewMCPCmd(
		func() string {
			baseURL, _ := requireBaseURL()
			return baseURL
		},
		func() string {
			apiKey, _ := requireAPIKey()
			return apiKey
		},
		func() int { return flagTimeout },
	))
}

func initConfig() {
	// Load config file first (lowest priority)
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] config parse error: %v\n", err)
	}

	// Environment variables override config file
	if v := os.Getenv("HELLOJOHN_BASE_URL"); v != "" {
		cfg.BaseURL = v
	}
	if v := os.Getenv("HELLOJOHN_API_KEY"); v != "" {
		cfg.APIKey = v
	}
	if v := os.Getenv("HELLOJOHN_DEFAULT_TENANT"); v != "" {
		cfg.DefaultTenant = v
	}
	if v := os.Getenv("HELLOJOHN_OUTPUT"); v != "" {
		cfg.Output = v
	}

	// Apply config/env values only when the flag was NOT explicitly passed on the
	// command line. Using .Changed() properly handles the case where the user
	// explicitly passes an empty string (which == "" check would mishandle).
	// CLI-21: use .Changed() instead of == "" for all persistent flags.
	if !rootCmd.PersistentFlags().Changed("base-url") && cfg.BaseURL != "" {
		flagBaseURL = cfg.BaseURL
	}
	if !rootCmd.PersistentFlags().Changed("api-key") && cfg.APIKey != "" {
		flagAPIKey = cfg.APIKey
	}
	if !rootCmd.PersistentFlags().Changed("tenant") && cfg.DefaultTenant != "" {
		flagTenant = cfg.DefaultTenant
	}
	if !rootCmd.PersistentFlags().Changed("output") && cfg.Output != "" {
		flagOutput = cfg.Output
	}
}

// requireAPIKey validates that an API key is available and returns it.
// Returns an error if not configured — caller must return this error to cobra RunE.
func requireAPIKey() (string, error) {
	if flagAPIKey == "" {
		return "", fmt.Errorf("no API key configured. Use --api-key, HELLOJOHN_API_KEY, or 'hjctl auth login'")
	}
	return flagAPIKey, nil
}

// requireBaseURL validates that a base URL is available and returns it.
// Returns an error if not configured — caller must return this error to cobra RunE.
func requireBaseURL() (string, error) {
	if flagBaseURL == "" {
		return "", fmt.Errorf("no base URL configured. Use --base-url, HELLOJOHN_BASE_URL, or 'hjctl auth login'")
	}
	return flagBaseURL, nil
}

// requireTenant validates that a tenant slug is available and returns it.
// Returns an error if not configured — caller must return this error to cobra RunE.
func requireTenant() (string, error) {
	if flagTenant == "" {
		return "", fmt.Errorf("no tenant specified. Use --tenant, HELLOJOHN_DEFAULT_TENANT, or config file")
	}
	return flagTenant, nil
}
