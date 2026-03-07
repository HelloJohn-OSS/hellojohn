package commands

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/dropDatabas3/hellojohn/cmd/hjctl/client"
	"github.com/spf13/cobra"
)

// NewAuditCmd creates the `audit` command group.
func NewAuditCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "audit",
		Aliases: []string{"audit-log"},
		Short:   "View audit logs (requires --tenant)",
	}

	cmd.AddCommand(&cobra.Command{
		Use: "list", Short: "List audit log entries",
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
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/audit-logs", &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use: "get <id>", Short: "Get audit log entry", Args: cobra.ExactArgs(1),
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
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/audit-logs/"+url.PathEscape(args[0]), &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	})

	var before string
	var forcePurge bool
	var dryRunPurge bool
	purgeCmd := &cobra.Command{
		Use:   "purge",
		Short: "Purge audit logs (optionally before a date)",
		Long:  "Permanently delete audit log entries. Use --before to limit deletion to entries older than a given date (RFC3339).",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !forcePurge {
				return fmt.Errorf("use --force to confirm purging audit logs")
			}
			t, err := getTenant()
			if err != nil {
				return err
			}
			if dryRunPurge {
				fmt.Fprintf(cmd.OutOrStdout(), "[dry-run] Would purge audit logs for tenant %s\n", t)
				return nil
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			// CLI-10: use url.Values to prevent query injection via the --before flag.
			params := url.Values{}
			if before != "" {
				params.Set("before", before)
			}
			path := "/v2/admin/tenants/" + url.PathEscape(t) + "/audit-logs"
			if len(params) > 0 {
				path += "?" + params.Encode()
			}
			if err := c.Delete(cmd.Context(), path, nil); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "Audit logs purged.")
			return nil
		},
	}
	purgeCmd.Flags().StringVar(&before, "before", "", "Delete entries before this RFC3339 timestamp")
	purgeCmd.Flags().BoolVar(&forcePurge, "force", false, "Skip confirmation prompt")
	purgeCmd.Flags().BoolVar(&dryRunPurge, "dry-run", false, "Preview what would be purged without actually deleting")
	cmd.AddCommand(purgeCmd)

	return cmd
}
