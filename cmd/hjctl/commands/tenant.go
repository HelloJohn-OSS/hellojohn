package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/dropDatabas3/hellojohn/cmd/hjctl/client"
	"github.com/spf13/cobra"
)

// NewTenantCmd creates the `tenant` command group.
func NewTenantCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "tenant",
		Aliases: []string{"tenants"},
		Short:   "Manage tenants",
	}

	cmd.AddCommand(newTenantListCmd(getClient, outputFmt))
	cmd.AddCommand(newTenantGetCmd(getClient, outputFmt))
	cmd.AddCommand(newTenantCreateCmd(getClient, outputFmt))
	cmd.AddCommand(newTenantDeleteCmd(getClient))
	cmd.AddCommand(newTenantExportCmd(getClient, outputFmt))
	cmd.AddCommand(newTenantUpdateCmd(getClient, outputFmt))
	cmd.AddCommand(newTenantGetSettingsCmd(getClient, outputFmt))
	cmd.AddCommand(newTenantSetSettingsCmd(getClient, outputFmt))
	// NICE-TO-HAVE
	cmd.AddCommand(newTenantImportCmd(getClient, outputFmt))
	cmd.AddCommand(newTenantCheckDBCmd(getClient, outputFmt))
	cmd.AddCommand(newTenantRotateKeysCmd(getClient, outputFmt))
	cmd.AddCommand(newTenantStatsCmd(getClient, outputFmt))
	cmd.AddCommand(newTenantListAdminsCmd(getClient, outputFmt))
	cmd.AddCommand(newTenantAddAdminCmd(getClient))
	cmd.AddCommand(newTenantRemoveAdminCmd(getClient))
	cmd.AddCommand(newTenantDisableCmd(getClient))
	cmd.AddCommand(newTenantEnableCmd(getClient))

	return cmd
}

func newTenantListCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	var page, limit int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all tenants",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Get(cmd.Context(), "/v2/admin/tenants"+paginationQuery(page, limit), &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
	addPaginationFlags(cmd, &page, &limit)
	return cmd
}

func newTenantGetCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	return &cobra.Command{
		Use:   "get <slug-or-id>",
		Short: "Get tenant details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(args[0]), &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
}

func newTenantCreateCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	var slug, name, lang string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			if slug == "" {
				return fmt.Errorf("--slug is required")
			}
			// Note: --name is optional (README incorrectly marks it as required).
			body := map[string]string{"slug": slug}
			if name != "" {
				body["name"] = name
			}
			if lang != "" {
				body["language"] = lang
			}

			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Post(cmd.Context(), "/v2/admin/tenants", body, &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}

	cmd.Flags().StringVar(&slug, "slug", "", "Tenant slug (required)")
	cmd.Flags().StringVar(&name, "name", "", "Tenant display name")
	cmd.Flags().StringVar(&lang, "language", "", "Tenant language (e.g., en, es)")
	_ = cmd.MarkFlagRequired("slug")

	return cmd
}

func newTenantDeleteCmd(getClient func() (*client.Client, error)) *cobra.Command {
	var dryRun bool
	var force bool
	cmd := &cobra.Command{
		Use:   "delete <slug-or-id>",
		Short: "Delete a tenant",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force {
				fmt.Fprintf(os.Stderr, "WARNING: This will permanently delete tenant %q and all its configuration.\n", args[0])
				fmt.Fprintf(os.Stderr, "Run with --force to confirm: hjctl tenant delete --force %s\n", args[0])
				return fmt.Errorf("deletion requires --force flag")
			}
			if dryRun {
				fmt.Fprintf(os.Stderr, "[DRY RUN] Would delete tenant %s\n", args[0])
				return nil
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			if err := c.Delete(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(args[0]), nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Tenant %s deleted.\n", args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Confirm deletion without interactive prompt")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print what would be done without making any changes")
	return cmd
}

func newTenantExportCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	return &cobra.Command{
		Use:   "export <slug-or-id>",
		Short: "Export tenant configuration",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(args[0])+"/export", &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
}

func newTenantUpdateCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	var name, lang string

	cmd := &cobra.Command{
		Use:   "update <slug-or-id>",
		Short: "Update a tenant's properties",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]string{}
			if name != "" {
				body["name"] = name
			}
			if lang != "" {
				body["language"] = lang
			}
			if len(body) == 0 {
				return fmt.Errorf("at least one of --name or --language must be provided")
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Put(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(args[0]), body, &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "New tenant display name")
	cmd.Flags().StringVar(&lang, "language", "", "New tenant language (e.g., en, es)")

	return cmd
}

func newTenantGetSettingsCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	return &cobra.Command{
		Use:   "get-settings <slug-or-id>",
		Short: "Get tenant settings",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(args[0])+"/settings", &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
}

func newTenantSetSettingsCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	var file string

	cmd := &cobra.Command{
		Use:   "set-settings <slug-or-id>",
		Short: "Update tenant settings from JSON file or stdin",
		Long: `Update tenant settings by providing a JSON payload.
Use --file to read from a file, or pipe JSON via stdin.

Example:
  hjctl tenant set-settings acme --file settings.json
  echo '{"smtp":{"host":"smtp.example.com"}}' | hjctl tenant set-settings acme`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var data []byte
			var err error
			if file != "" {
				data, err = os.ReadFile(file)
				if err != nil {
					return fmt.Errorf("read file: %w", err)
				}
			} else {
				data, err = io.ReadAll(os.Stdin)
				if err != nil {
					return fmt.Errorf("read stdin: %w", err)
				}
			}

			var body json.RawMessage
			if err := json.Unmarshal(data, &body); err != nil {
				return fmt.Errorf("invalid JSON: %w", err)
			}

			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Put(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(args[0])+"/settings", body, &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}

	cmd.Flags().StringVarP(&file, "file", "f", "", "Path to JSON file with settings")

	return cmd
}

func newTenantImportCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	var file string

	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import a tenant from a JSON export file or stdin",
		RunE: func(cmd *cobra.Command, args []string) error {
			var data []byte
			var err error
			if file != "" {
				data, err = os.ReadFile(file)
				if err != nil {
					return fmt.Errorf("read file: %w", err)
				}
			} else {
				data, err = io.ReadAll(os.Stdin)
				if err != nil {
					return fmt.Errorf("read stdin: %w", err)
				}
			}
			var body json.RawMessage
			if err := json.Unmarshal(data, &body); err != nil {
				return fmt.Errorf("invalid JSON: %w", err)
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Post(cmd.Context(), "/v2/admin/tenants/import", body, &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}

	cmd.Flags().StringVarP(&file, "file", "f", "", "Path to JSON export file (default: stdin)")

	return cmd
}

func newTenantCheckDBCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	return &cobra.Command{
		Use:   "check-db <slug-or-id>",
		Short: "Check tenant database connectivity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(args[0])+"/check-db", &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
}

func newTenantRotateKeysCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	var forceRotate bool
	cmd := &cobra.Command{
		Use:   "rotate-keys <slug-or-id>",
		Short: "Rotate JWT signing keys for a tenant (deprecated: use 'hjctl key rotate')",
		Long:  "Rotate JWT signing keys for a tenant.\n\nDeprecated: prefer 'hjctl key rotate --tenant <slug>' which is the canonical key management command.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintln(os.Stderr, "[DEPRECATED] 'tenant rotate-keys' is deprecated — use 'hjctl key rotate --tenant <slug> --force' instead.")
			if !forceRotate {
				return fmt.Errorf("use --force to confirm rotating keys for tenant %s (invalidates ALL active JWTs)", args[0])
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Post(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(args[0])+"/keys/rotate", nil, &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
	cmd.Flags().BoolVar(&forceRotate, "force", false, "Confirm key rotation (invalidates ALL active JWTs for this tenant)")
	// Mark as deprecated so the CLI help shows the deprecation message.
	_ = cmd.Flags().MarkDeprecated("force", "use 'hjctl key rotate --tenant <slug> --force' instead")
	return cmd
}

func newTenantStatsCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	return &cobra.Command{
		Use:   "stats <slug-or-id>",
		Short: "Get tenant statistics (user count, sessions, etc.)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(args[0])+"/stats", &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
}

func newTenantListAdminsCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	return &cobra.Command{
		Use:   "list-admins <slug-or-id>",
		Short: "List admin users for a tenant",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(args[0])+"/admins", &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
}

func newTenantAddAdminCmd(getClient func() (*client.Client, error)) *cobra.Command {
	var sub string

	cmd := &cobra.Command{
		Use:   "add-admin <slug-or-id>",
		Short: "Grant admin rights to a user in a tenant",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if sub == "" {
				return fmt.Errorf("--sub is required")
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			body := map[string]string{"sub": sub}
			if err := c.Post(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(args[0])+"/admins", body, nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Admin %s added to tenant %s.\n", sub, args[0])
			return nil
		},
	}

	cmd.Flags().StringVar(&sub, "sub", "", "User UUID to grant admin rights (required)")
	_ = cmd.MarkFlagRequired("sub")

	return cmd
}

func newTenantRemoveAdminCmd(getClient func() (*client.Client, error)) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "remove-admin <slug-or-id> <sub>",
		Short: "Revoke admin rights from a user in a tenant",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force {
				fmt.Fprintf(os.Stderr, "WARNING: This will revoke admin rights of user %q from tenant %q.\n", args[1], args[0])
				fmt.Fprintf(os.Stderr, "Run with --force to confirm: hjctl tenant remove-admin --force %s %s\n", args[0], args[1])
				return fmt.Errorf("remove-admin requires --force flag")
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			if err := c.Delete(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(args[0])+"/admins/"+url.PathEscape(args[1]), nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Admin %s removed from tenant %s.\n", args[1], args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Confirm removing admin rights without interactive prompt")
	return cmd
}

func newTenantDisableCmd(getClient func() (*client.Client, error)) *cobra.Command {
	var dryRun bool
	var forceDisable bool
	cmd := &cobra.Command{
		Use:   "disable <slug-or-id>",
		Short: "Disable a tenant",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !forceDisable {
				return fmt.Errorf("use --force to confirm disabling tenant %s (this blocks ALL active users)", args[0])
			}
			if dryRun {
				fmt.Fprintf(os.Stderr, "[DRY RUN] Would disable tenant %s\n", args[0])
				return nil
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			if err := c.Post(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(args[0])+"/disable", nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Tenant %s disabled.\n", args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&forceDisable, "force", false, "Confirm disabling the tenant (blocks all active users)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print what would be done without making any changes")
	return cmd
}

func newTenantEnableCmd(getClient func() (*client.Client, error)) *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "enable <slug-or-id>",
		Short: "Enable a disabled tenant",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if dryRun {
				fmt.Fprintf(os.Stderr, "[DRY RUN] Would enable tenant %s\n", args[0])
				return nil
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			if err := c.Post(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(args[0])+"/enable", nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Tenant %s enabled.\n", args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print what would be done without making any changes")
	return cmd
}
