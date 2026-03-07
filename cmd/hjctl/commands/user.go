package commands

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/dropDatabas3/hellojohn/cmd/hjctl/client"
	"github.com/spf13/cobra"
)

// NewUserCmd creates the `user` command group.
func NewUserCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "user",
		Aliases: []string{"users"},
		Short:   "Manage users (requires --tenant)",
	}

	cmd.AddCommand(newUserListCmd(getClient, outputFmt, getTenant))
	cmd.AddCommand(newUserGetCmd(getClient, outputFmt, getTenant))
	cmd.AddCommand(newUserCreateCmd(getClient, outputFmt, getTenant))
	cmd.AddCommand(newUserDeleteCmd(getClient, getTenant))
	cmd.AddCommand(newUserUpdateCmd(getClient, outputFmt, getTenant))
	cmd.AddCommand(newUserDisableCmd(getClient, getTenant))
	cmd.AddCommand(newUserEnableCmd(getClient, getTenant))
	cmd.AddCommand(newUserSetPasswordCmd(getClient, getTenant))
	cmd.AddCommand(newUserListRolesCmd(getClient, outputFmt, getTenant))
	cmd.AddCommand(newUserAssignRoleCmd(getClient, getTenant))
	cmd.AddCommand(newUserRemoveRoleCmd(getClient, getTenant))

	return cmd
}

func tenantUsersPath(tenant string) string {
	return "/v2/admin/tenants/" + url.PathEscape(tenant) + "/users"
}

func newUserListCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	var page, limit int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List users in a tenant",
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
			if err := c.Get(cmd.Context(), tenantUsersPath(t)+paginationQuery(page, limit), &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
	addPaginationFlags(cmd, &page, &limit)
	return cmd
}

func newUserGetCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "get <user-id>",
		Short: "Get user details",
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
			var result json.RawMessage
			if err := c.Get(cmd.Context(), tenantUsersPath(t)+"/"+url.PathEscape(args[0]), &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
}

func newUserCreateCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	var email, password, name string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a user",
		RunE: func(cmd *cobra.Command, args []string) error {
			if email == "" {
				return fmt.Errorf("--email is required")
			}
			t, err := getTenant()
			if err != nil {
				return err
			}
			body := map[string]string{"email": email}
			if name != "" {
				body["name"] = name
			}
			if password != "" {
				fmt.Fprintln(os.Stderr, "[WARN] Passing --password via CLI flag exposes it in shell history and process list. Consider omitting it and setting the password with 'set-password' after creation.")
				body["password"] = password
			}

			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Post(cmd.Context(), tenantUsersPath(t), body, &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}

	cmd.Flags().StringVar(&email, "email", "", "User email (required)")
	cmd.Flags().StringVar(&password, "password", "", "User password")
	cmd.Flags().StringVar(&name, "name", "", "User display name")

	return cmd
}

func newUserDeleteCmd(getClient func() (*client.Client, error), getTenant func() (string, error)) *cobra.Command {
	var force bool
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "delete <user-id>",
		Short: "Delete a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force {
				return fmt.Errorf("use --force to confirm deletion of user %s", args[0])
			}
			if dryRun {
				fmt.Fprintf(os.Stderr, "[DRY RUN] Would delete user %s\n", args[0])
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
			if err := c.Delete(cmd.Context(), tenantUsersPath(t)+"/"+url.PathEscape(args[0]), nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "User %s deleted.\n", args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Confirm deletion without interactive prompt")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print what would be done without making any changes")
	return cmd
}

func newUserUpdateCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	var name, email string

	cmd := &cobra.Command{
		Use:   "update <user-id>",
		Short: "Update a user's properties",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]string{}
			if name != "" {
				body["name"] = name
			}
			if email != "" {
				body["email"] = email
			}
			if len(body) == 0 {
				return fmt.Errorf("at least one of --name or --email must be provided")
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
			if err := c.Put(cmd.Context(), tenantUsersPath(t)+"/"+url.PathEscape(args[0]), body, &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "New display name")
	cmd.Flags().StringVar(&email, "email", "", "New email address")

	return cmd
}

func newUserDisableCmd(getClient func() (*client.Client, error), getTenant func() (string, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "disable <user-id>",
		Short: "Disable a user account",
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
			if err := c.Post(cmd.Context(), tenantUsersPath(t)+"/"+url.PathEscape(args[0])+"/disable", nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "User %s disabled.\n", args[0])
			return nil
		},
	}
}

func newUserEnableCmd(getClient func() (*client.Client, error), getTenant func() (string, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "enable <user-id>",
		Short: "Enable a user account",
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
			if err := c.Post(cmd.Context(), tenantUsersPath(t)+"/"+url.PathEscape(args[0])+"/enable", nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "User %s enabled.\n", args[0])
			return nil
		},
	}
}

func newUserSetPasswordCmd(getClient func() (*client.Client, error), getTenant func() (string, error)) *cobra.Command {
	var password string

	cmd := &cobra.Command{
		Use:   "set-password <user-id>",
		Short: "Set a new password for a user (admin override)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// NOTE: --password via CLI exposes the value in shell history and in
			// /proc/<pid>/cmdline. Prefer interactive input or environment variable
			// injection in production scripts.
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			body := map[string]string{"password": password}
			if err := c.Post(cmd.Context(), tenantUsersPath(t)+"/"+url.PathEscape(args[0])+"/set-password", body, nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Password updated for user %s.\n", args[0])
			return nil
		},
	}

	cmd.Flags().StringVar(&password, "password", "", "New password")
	_ = cmd.MarkFlagRequired("password")

	return cmd
}

func newUserListRolesCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "list-roles <user-id>",
		Short: "List roles assigned to a user",
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
			var result json.RawMessage
			if err := c.Get(cmd.Context(), tenantUsersPath(t)+"/"+url.PathEscape(args[0])+"/roles", &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
}

func newUserAssignRoleCmd(getClient func() (*client.Client, error), getTenant func() (string, error)) *cobra.Command {
	var role string

	cmd := &cobra.Command{
		Use:   "assign-role <user-id>",
		Short: "Assign a role to a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if role == "" {
				return fmt.Errorf("--role is required")
			}
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			body := map[string]string{"role": role}
			if err := c.Post(cmd.Context(), tenantUsersPath(t)+"/"+url.PathEscape(args[0])+"/roles", body, nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Role %s assigned to user %s.\n", role, args[0])
			return nil
		},
	}

	cmd.Flags().StringVar(&role, "role", "", "Role name to assign (required)")
	_ = cmd.MarkFlagRequired("role")

	return cmd
}

func newUserRemoveRoleCmd(getClient func() (*client.Client, error), getTenant func() (string, error)) *cobra.Command {
	var role string

	cmd := &cobra.Command{
		Use:   "remove-role <user-id>",
		Short: "Remove a role from a user",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if role == "" {
				return fmt.Errorf("--role is required")
			}
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			if err := c.Delete(cmd.Context(), tenantUsersPath(t)+"/"+url.PathEscape(args[0])+"/roles/"+url.PathEscape(role), nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Role %s removed from user %s.\n", role, args[0])
			return nil
		},
	}

	cmd.Flags().StringVar(&role, "role", "", "Role name to remove (required)")
	_ = cmd.MarkFlagRequired("role")

	return cmd
}
