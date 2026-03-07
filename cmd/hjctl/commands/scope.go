package commands

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/dropDatabas3/hellojohn/cmd/hjctl/client"
	"github.com/spf13/cobra"
)

// NewScopeCmd creates the `scope` command group.
func NewScopeCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "scope",
		Aliases: []string{"scopes"},
		Short:   "Manage OAuth scopes (requires --tenant)",
	}

	cmd.AddCommand(newScopeListCmd(getTenant, getClient, outputFmt))

	var name, desc string
	createCmd := &cobra.Command{
		Use: "create", Short: "Create a scope",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}
			t, err := getTenant()
			if err != nil {
				return err
			}
			body := map[string]string{"name": name}
			if desc != "" {
				body["description"] = desc
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Post(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/scopes", body, &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
	createCmd.Flags().StringVar(&name, "name", "", "Scope name (required)")
	createCmd.Flags().StringVar(&desc, "description", "", "Scope description")
	cmd.AddCommand(createCmd)

	var forceDelete bool
	var dryRunDelete bool
	deleteCmd := &cobra.Command{
		Use: "delete <name>", Short: "Delete a scope", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !forceDelete {
				return fmt.Errorf("use --force to confirm this destructive operation")
			}
			t, err := getTenant()
			if err != nil {
				return err
			}
			if dryRunDelete {
				fmt.Fprintf(cmd.OutOrStdout(), "[dry-run] Would delete scope %s from tenant %s\n", args[0], t)
				return nil
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			if err := c.Delete(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/scopes/"+url.PathEscape(args[0]), nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Scope %s deleted.\n", args[0])
			return nil
		},
	}
	deleteCmd.Flags().BoolVar(&forceDelete, "force", false, "Skip confirmation prompt")
	deleteCmd.Flags().BoolVar(&dryRunDelete, "dry-run", false, "Preview what would be deleted without actually deleting")
	cmd.AddCommand(deleteCmd)

	cmd.AddCommand(&cobra.Command{
		Use: "get <name>", Short: "Get a scope by name", Args: cobra.ExactArgs(1),
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
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/scopes/"+url.PathEscape(args[0]), &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	})

	return cmd
}
func newScopeListCmd(getTenant func() (string, error), getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	var page, limit int
	cmd := &cobra.Command{
		Use: "list", Short: "List scopes",
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
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/scopes"+paginationQuery(page, limit), &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
	addPaginationFlags(cmd, &page, &limit)
	return cmd
}
