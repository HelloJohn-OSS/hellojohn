package commands

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/dropDatabas3/hellojohn/cmd/hjctl/client"
	"github.com/spf13/cobra"
)

// NewRoleCmd creates the `role` command group.
func NewRoleCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "role",
		Aliases: []string{"roles"},
		Short:   "Manage RBAC roles (requires --tenant)",
	}

	cmd.AddCommand(newRoleListCmd(getTenant, getClient, outputFmt))

	cmd.AddCommand(&cobra.Command{
		Use: "get <name>", Short: "Get role details", Args: cobra.ExactArgs(1),
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
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/rbac/roles/"+url.PathEscape(args[0]), &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	})

	// role delete
	var forceDeleteRole bool
	var dryRunDeleteRole bool
	deleteCmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a role",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !forceDeleteRole {
				return fmt.Errorf("deleting a role silently removes permissions from all assigned users; use --force to confirm")
			}
			if dryRunDeleteRole {
				fmt.Fprintf(os.Stderr, "[DRY RUN] Would delete role %s from tenant\n", args[0])
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
			if err := c.Delete(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/rbac/roles/"+url.PathEscape(args[0]), nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Role %s deleted.\n", args[0])
			return nil
		},
	}
	deleteCmd.Flags().BoolVar(&forceDeleteRole, "force", false, "Confirm deletion (removes permissions from all assigned users)")
	deleteCmd.Flags().BoolVar(&dryRunDeleteRole, "dry-run", false, "Print what would be done without making any changes")
	cmd.AddCommand(deleteCmd)

	// role create
	var createDesc, createPerms string
	createCmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new role",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			body := map[string]interface{}{"name": args[0]}
			if createDesc != "" {
				body["description"] = createDesc
			}
			if createPerms != "" {
				perms := strings.Split(createPerms, ",")
				for i, p := range perms {
					perms[i] = strings.TrimSpace(p)
				}
				body["permissions"] = perms
			}
			var result json.RawMessage
			if err := c.Post(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/rbac/roles", body, &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
	createCmd.Flags().StringVar(&createDesc, "description", "", "Role description")
	createCmd.Flags().StringVar(&createPerms, "permissions", "", "Comma-separated initial permissions")
	cmd.AddCommand(createCmd)

	// role update
	var updateDesc, addPerms, removePerms string
	updateCmd := &cobra.Command{
		Use:   "update <name>",
		Short: "Update a role's description or permissions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]interface{}{}
			if updateDesc != "" {
				body["description"] = updateDesc
			}
			if addPerms != "" {
				perms := strings.Split(addPerms, ",")
				for i, p := range perms {
					perms[i] = strings.TrimSpace(p)
				}
				body["add_permissions"] = perms
			}
			if removePerms != "" {
				perms := strings.Split(removePerms, ",")
				for i, p := range perms {
					perms[i] = strings.TrimSpace(p)
				}
				body["remove_permissions"] = perms
			}
			if len(body) == 0 {
				return fmt.Errorf("at least one of --description, --add-permissions, or --remove-permissions must be provided")
			}
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Put(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/rbac/roles/"+url.PathEscape(args[0]), body, &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
	updateCmd.Flags().StringVar(&updateDesc, "description", "", "New description")
	updateCmd.Flags().StringVar(&addPerms, "add-permissions", "", "Comma-separated permissions to add")
	updateCmd.Flags().StringVar(&removePerms, "remove-permissions", "", "Comma-separated permissions to remove")
	cmd.AddCommand(updateCmd)

	return cmd
}

func newRoleListCmd(getTenant func() (string, error), getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	var page, limit int
	cmd := &cobra.Command{
		Use: "list", Short: "List roles",
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
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/rbac/roles"+paginationQuery(page, limit), &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
	addPaginationFlags(cmd, &page, &limit)
	return cmd
}
