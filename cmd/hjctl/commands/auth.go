package commands

import (
	"fmt"
	"os"

	"github.com/dropDatabas3/hellojohn/cmd/hjctl/client"
	"github.com/spf13/cobra"
)

// NewAuthCmd creates the `auth` command group.
// CLI-16: getBaseURL/getAPIKey closures read the persistent flags so auth login
// does NOT redefine --base-url/--api-key locally (shadowing the parent FlagSet).
// CLI-17: getTimeout closure forwards the global --timeout value to the client.
func NewAuthCmd(getBaseURL func() string, getAPIKey func() string, getTimeout func() int, saveCfg func(baseURL, apiKey string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authentication and configuration",
	}

	cmd.AddCommand(newAuthLoginCmd(getBaseURL, getAPIKey, getTimeout, saveCfg))
	cmd.AddCommand(newAuthLogoutCmd(saveCfg))
	cmd.AddCommand(newAuthWhoamiCmd(getBaseURL, getAPIKey))

	return cmd
}

// adminLoginResponse mirrors the relevant fields of AdminLoginResult.
type adminLoginResponse struct {
	AccessToken string `json:"access_token"`
}

// apiKeyCreateResponse mirrors the wrapped response of POST /v2/admin/api-keys.
// The controller returns {"data": {...}}.
type apiKeyCreateResponse struct {
	Data struct {
		Token string `json:"token"`
		Name  string `json:"name"`
		ID    string `json:"id"`
	} `json:"data"`
}

// newAuthLoginCmd saves credentials to config.
//
// Two authentication modes:
//
//  1. API key (existing):   hjctl auth login --base-url <url> --api-key <key>
//     Validates the key and saves it.
//
//  2. Email + password:     hjctl auth login --base-url <url> --email <e> --password <p>
//     Calls POST /v2/admin/login → gets JWT → creates a new API key
//     named "hjctl-auto" with admin scope → saves the new key to config.
//     The raw JWT is never stored; only the durable API key is kept.
//
// --base-url/--api-key are inherited PersistentFlags from root (CLI-16).
func newAuthLoginCmd(getBaseURL func() string, getAPIKey func() string, getTimeout func() int, saveCfg func(baseURL, apiKey string) error) *cobra.Command {
	var email, password string

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate and save credentials to config",
		Long: `Authenticate against a HelloJohn instance and save credentials.

Two modes:

  API key (if you already have one):
    hjctl auth login --base-url https://auth.example.com --api-key hj_...

  Email + password (bootstrap or convenience):
    hjctl auth login --base-url https://auth.example.com --email admin@example.com --password secret
    hjctl will obtain an admin JWT, then automatically create and save a new
    API key named "hjctl-auto" so you never have to manage keys manually.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			baseURL := getBaseURL()
			if baseURL == "" {
				return fmt.Errorf("--base-url is required (or set HELLOJOHN_BASE_URL)")
			}

			apiKey := getAPIKey()
			useEmailFlow := email != "" || password != ""

			// — Mode 1: API key validation (existing behaviour) —
			if !useEmailFlow {
				if apiKey == "" {
					return fmt.Errorf("provide --api-key OR --email + --password")
				}
				c := client.New(baseURL, apiKey, getTimeout())
				var result any
				if err := c.Get(cmd.Context(), "/v2/admin/api-keys", &result); err != nil {
					return fmt.Errorf("authentication failed: %w", err)
				}
				if err := saveCfg(baseURL, apiKey); err != nil {
					return fmt.Errorf("save config: %w", err)
				}
				fmt.Fprintln(os.Stderr, "Authenticated successfully. Config saved.")
				return nil
			}

			// — Mode 2: Email + password bootstrap —
			if email == "" || password == "" {
				return fmt.Errorf("both --email and --password are required")
			}

			// Step 1: obtain JWT
			anonClient := client.New(baseURL, "", getTimeout())
			var loginResp adminLoginResponse
			if err := anonClient.Post(cmd.Context(), "/v2/admin/login",
				map[string]string{"email": email, "password": password},
				&loginResp,
			); err != nil {
				return fmt.Errorf("login failed: %w", err)
			}
			if loginResp.AccessToken == "" {
				return fmt.Errorf("login succeeded but no access_token in response")
			}

			// Step 2: create API key using the JWT
			var keyResp apiKeyCreateResponse
			if err := anonClient.PostWithBearer(cmd.Context(), "/v2/admin/api-keys",
				loginResp.AccessToken,
				map[string]string{"name": "hjctl-auto", "scope": "admin"},
				&keyResp,
			); err != nil {
				return fmt.Errorf("create API key failed: %w", err)
			}
			if keyResp.Data.Token == "" {
				return fmt.Errorf("API key created but token missing in response")
			}

			// Step 3: save
			if err := saveCfg(baseURL, keyResp.Data.Token); err != nil {
				return fmt.Errorf("save config: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Authenticated as %s. API key %q created and saved.\n", email, keyResp.Data.Name)
			return nil
		},
	}

	cmd.Flags().StringVar(&email, "email", "", "Admin email address (for email+password login)")
	cmd.Flags().StringVar(&password, "password", "", "Admin password (for email+password login)")

	return cmd
}

func newAuthLogoutCmd(saveCfg func(baseURL, apiKey string) error) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove API key from config",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := saveCfg("", ""); err != nil {
				return fmt.Errorf("save config: %w", err)
			}
			fmt.Fprintln(os.Stderr, "Logged out. API key removed from config.")
			return nil
		},
	}
}

// newAuthWhoamiCmd shows the currently configured credentials without making
// an HTTP request. The API key is masked to avoid leaking secrets in terminal
// output or shell history.
// CLI-18: shows config (masked) instead of listing ALL API keys.
func newAuthWhoamiCmd(getBaseURL func() string, getAPIKey func() string) *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show current CLI credentials (base URL and masked API key)",
		RunE: func(cmd *cobra.Command, args []string) error {
			baseURL := getBaseURL()
			apiKey := getAPIKey()
			if baseURL == "" {
				baseURL = "(not configured)"
			}
			fmt.Printf("base-url: %s\napi-key:  %s\n", baseURL, maskAPIKey(apiKey))
			return nil
		},
	}
}

// NewConfigCmd creates the `config` command group.
func NewConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage CLI configuration",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "set <key> <value>",
		Short: "Set a config value",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return setConfigValue(args[0], args[1])
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "get <key>",
		Short: "Get a config value",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return getConfigValue(args[0])
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Show all config values",
		RunE: func(cmd *cobra.Command, args []string) error {
			return showConfig()
		},
	})

	return cmd
}
