package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/dropDatabas3/hellojohn/cmd/hjctl/client"
	"github.com/spf13/cobra"
)

// NewSystemCmd creates the `system` command group.
func NewSystemCmd(getClient func() (*client.Client, error), outputFmt func() string, getBaseURL func() (string, error), getTimeout func() int) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "system",
		Short: "System health and diagnostics",
	}

	cmd.AddCommand(&cobra.Command{
		Use: "health", Short: "Check server health",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Health endpoint is public — use direct HTTP request without API key
			baseURL, err := getBaseURL()
			if err != nil {
				return err
			}
			httpClient := &http.Client{Timeout: time.Duration(getTimeout()) * time.Second}
			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, baseURL+"/readyz", nil)
			if err != nil {
				return fmt.Errorf("health check: build request: %w", err)
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				return fmt.Errorf("health check failed: %w", err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("health check: read response: %w", err)
			}
			prettyPrint(body, outputFmt())
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use: "ready", Short: "Check server readiness",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Ready endpoint is public — use direct HTTP request without API key
			baseURL, err := getBaseURL()
			if err != nil {
				return err
			}
			httpClient := &http.Client{Timeout: time.Duration(getTimeout()) * time.Second}
			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, baseURL+"/readyz", nil)
			if err != nil {
				return fmt.Errorf("readiness check: build request: %w", err)
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				return fmt.Errorf("readiness check failed: %w", err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("readiness check: read response: %w", err)
			}
			prettyPrint(body, outputFmt())
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use: "cluster", Short: "Get cluster status",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Get(cmd.Context(), "/v2/admin/cluster/nodes", &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	})

	cmd.AddCommand(NewSystemMailCmd(getClient, outputFmt))

	return cmd
}

// NewWebhookCmd creates the `webhook` command group.
func NewWebhookCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "webhook",
		Aliases: []string{"webhooks"},
		Short:   "Manage webhooks (requires --tenant)",
	}

	cmd.AddCommand(&cobra.Command{
		Use: "list", Short: "List webhooks",
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/webhooks", &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	})

	var webhookURL, webhookSecret, webhookEvents string
	createWebhookCmd := &cobra.Command{
		Use: "create", Short: "Create a webhook endpoint",
		RunE: func(cmd *cobra.Command, args []string) error {
			if webhookURL == "" {
				return fmt.Errorf("--url is required")
			}
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			body := map[string]interface{}{"url": webhookURL}
			if webhookSecret != "" {
				body["secret"] = webhookSecret
			}
			if webhookEvents != "" {
				body["events"] = splitAndTrim(webhookEvents, ",")
			}
			var result json.RawMessage
			if err := c.Post(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/webhooks", body, &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
	createWebhookCmd.Flags().StringVar(&webhookURL, "url", "", "Webhook endpoint URL (required)")
	createWebhookCmd.Flags().StringVar(&webhookSecret, "secret", "", "Signing secret (stored in plaintext — rotate regularly)")
	createWebhookCmd.Flags().StringVar(&webhookEvents, "events", "", "Comma-separated event types (e.g., user.created,user.deleted)")
	cmd.AddCommand(createWebhookCmd)

	var forceWebhookDelete bool
	var dryRunWebhookDelete bool
	deleteWebhookCmd := &cobra.Command{
		Use: "delete <id>", Short: "Delete a webhook", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !forceWebhookDelete {
				return fmt.Errorf("use --force to confirm deleting webhook %s", args[0])
			}
			if dryRunWebhookDelete {
				fmt.Fprintf(os.Stderr, "[DRY RUN] Would delete webhook %s\n", args[0])
				return nil
			}
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			if err := c.Delete(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/webhooks/"+url.PathEscape(args[0]), nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Webhook %s deleted.\n", args[0])
			return nil
		},
	}
	deleteWebhookCmd.Flags().BoolVar(&forceWebhookDelete, "force", false, "Skip confirmation prompt")
	deleteWebhookCmd.Flags().BoolVar(&dryRunWebhookDelete, "dry-run", false, "Print what would be done without making any changes")
	cmd.AddCommand(deleteWebhookCmd)

	cmd.AddCommand(&cobra.Command{
		Use: "test <id>", Short: "Send a test event to a webhook", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Post(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/webhooks/"+url.PathEscape(args[0])+"/test", nil, &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	})

	return cmd
}

// NewSessionCmd creates the `session` command group.
func NewSessionCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "session",
		Aliases: []string{"sessions"},
		Short:   "Manage sessions (requires --tenant)",
	}

	cmd.AddCommand(&cobra.Command{
		Use: "list", Short: "List active sessions",
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/sessions", &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	})

	var forceRevoke bool
	revokeCmd := &cobra.Command{
		Use: "revoke <session-id>", Short: "Revoke a specific session", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !forceRevoke {
				fmt.Fprintf(os.Stderr, "WARNING: This will permanently revoke session %q.\n", args[0])
				fmt.Fprintf(os.Stderr, "Run with --force to confirm: hjctl session revoke --force %s\n", args[0])
				return fmt.Errorf("revoke requires --force flag")
			}
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			if err := c.Post(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/sessions/"+url.PathEscape(args[0])+"/revoke", nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Session %s revoked.\n", args[0])
			return nil
		},
	}
	revokeCmd.Flags().BoolVar(&forceRevoke, "force", false, "Confirm revoking the session without interactive prompt")
	cmd.AddCommand(revokeCmd)

	var forceRevokeAll bool
	revokeAllCmd := &cobra.Command{
		Use: "revoke-all", Short: "Revoke all active sessions for the tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := getTenant()
			if err != nil {
				return err
			}
			if !forceRevokeAll {
				return fmt.Errorf("use --force to confirm revoking ALL sessions for tenant %s", t)
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			if err := c.Post(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/sessions/revoke-all", map[string]any{}, nil); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "All sessions revoked.")
			return nil
		},
	}
	revokeAllCmd.Flags().BoolVar(&forceRevokeAll, "force", false, "Confirm revoking ALL sessions without interactive prompt")
	cmd.AddCommand(revokeAllCmd)

	return cmd
}

// NewMFACmd creates the `mfa` command group.
func NewMFACmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mfa",
		Short: "MFA configuration (requires --tenant)",
	}

	cmd.AddCommand(&cobra.Command{
		Use: "status", Short: "Get MFA status",
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/mfa/status", &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use: "config", Short: "Get MFA configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/mfa/config", &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	})

	var requireMFA bool
	enforceCmd := &cobra.Command{
		Use:   "enforce",
		Short: "Enable or disable MFA requirement for the tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			body := map[string]bool{"required": requireMFA}
			var result json.RawMessage
			if err := c.Post(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/mfa/enforce", body, &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
	enforceCmd.Flags().BoolVar(&requireMFA, "require", true, "Set to true to require MFA, false to disable requirement")
	// Note (CLI-27): flag is --require in code; README incorrectly documents it as --enabled.
	cmd.AddCommand(enforceCmd)

	var forceMFAReset bool
	mfaResetCmd := &cobra.Command{
		Use:   "reset <user-id>",
		Short: "Reset MFA for a specific user (admin override)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !forceMFAReset {
				return fmt.Errorf("use --force to confirm resetting MFA for user %s (removes all enrolled devices)", args[0])
			}
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			if err := c.Post(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/users/"+url.PathEscape(args[0])+"/mfa/reset", nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "MFA reset for user %s.\n", args[0])
			return nil
		},
	}
	mfaResetCmd.Flags().BoolVar(&forceMFAReset, "force", false, "Confirm resetting MFA (removes all enrolled devices)")
	cmd.AddCommand(mfaResetCmd)

	return cmd
}

// NewTokenCmd creates the `token` command group for managing OAuth tokens.
func NewTokenCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "token",
		Aliases: []string{"tokens"},
		Short:   "Manage OAuth tokens (requires --tenant)",
	}

	cmd.AddCommand(&cobra.Command{
		Use: "list", Short: "List active tokens",
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/tokens", &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	})

	var forceTokenRevoke bool
	var dryRunTokenRevoke bool
	revokeTokenCmd := &cobra.Command{
		Use: "revoke <token-id>", Short: "Revoke a token", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !forceTokenRevoke {
				return fmt.Errorf("use --force to confirm revoking token %s", args[0])
			}
			if dryRunTokenRevoke {
				fmt.Fprintf(os.Stderr, "[DRY RUN] Would revoke token %s\n", args[0])
				return nil
			}
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			if err := c.Delete(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/tokens/"+url.PathEscape(args[0]), nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Token %s revoked.\n", args[0])
			return nil
		},
	}
	revokeTokenCmd.Flags().BoolVar(&forceTokenRevoke, "force", false, "Skip confirmation prompt")
	revokeTokenCmd.Flags().BoolVar(&dryRunTokenRevoke, "dry-run", false, "Print what would be done without making any changes")
	cmd.AddCommand(revokeTokenCmd)

	return cmd
}

// NewConsentCmd creates the `consent` command group for managing OAuth consents.
func NewConsentCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "consent",
		Aliases: []string{"consents"},
		Short:   "Manage OAuth consents (requires --tenant)",
	}

	cmd.AddCommand(&cobra.Command{
		Use: "list", Short: "List granted consents",
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/consents", &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	})

	var forceConsentRevoke bool
	var dryRunConsentRevoke bool
	revokeConsentCmd := &cobra.Command{
		Use: "revoke <consent-id>", Short: "Revoke a consent grant", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !forceConsentRevoke {
				return fmt.Errorf("use --force to confirm revoking consent %s", args[0])
			}
			if dryRunConsentRevoke {
				fmt.Fprintf(os.Stderr, "[DRY RUN] Would revoke consent %s\n", args[0])
				return nil
			}
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			if err := c.Delete(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/consents/"+url.PathEscape(args[0]), nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Consent %s revoked.\n", args[0])
			return nil
		},
	}
	revokeConsentCmd.Flags().BoolVar(&forceConsentRevoke, "force", false, "Skip confirmation prompt")
	revokeConsentCmd.Flags().BoolVar(&dryRunConsentRevoke, "dry-run", false, "Print what would be done without making any changes")
	cmd.AddCommand(revokeConsentCmd)

	return cmd
}

// NewClaimCmd creates the `claim` command group.
func NewClaimCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "claim",
		Aliases: []string{"claims"},
		Short:   "Manage JWT claims (requires --tenant)",
		Long:    "Manage tenant-specific JWT claims configuration. Currently supports list only. create, update, and delete will be available in a future release.",
	}

	cmd.AddCommand(&cobra.Command{
		Use: "list", Short: "List custom claims",
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/claims", &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	})

	// TODO(CLI-29): add `claim create` — POST /v2/admin/tenants/{t}/claims with {name, key, value_template, description}
	// TODO(CLI-29): add `claim update <name>` — PATCH /v2/admin/tenants/{t}/claims/{name} with updated fields
	// TODO(CLI-29): add `claim delete <name>` — DELETE /v2/admin/tenants/{t}/claims/{name} (requires --force)

	return cmd
}
