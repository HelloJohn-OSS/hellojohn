package commands

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/dropDatabas3/hellojohn/cmd/hjctl/client"
	"github.com/spf13/cobra"
)

// NewInvitationCmd creates the `invitation` command group.
func NewInvitationCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "invitation",
		Aliases: []string{"invitations", "invite"},
		Short:   "Manage user invitations (requires --tenant)",
	}

	cmd.AddCommand(&cobra.Command{
		Use: "list", Short: "List pending invitations",
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
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/invitations", &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	})

	var email, role string
	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Invite a user by email",
		RunE: func(cmd *cobra.Command, args []string) error {
			if email == "" {
				return fmt.Errorf("--email is required")
			}
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			body := map[string]string{"email": email}
			if role != "" {
				body["role"] = role
			}
			var result json.RawMessage
			if err := c.Post(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/invitations", body, &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
	createCmd.Flags().StringVar(&email, "email", "", "Email address to invite (required)")
	createCmd.Flags().StringVar(&role, "role", "", "Role to assign on acceptance")
	cmd.AddCommand(createCmd)

	var forceDeleteInvitation bool
	deleteInvitationCmd := &cobra.Command{
		Use: "delete <id>", Short: "Delete a pending invitation", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !forceDeleteInvitation {
				fmt.Fprintf(os.Stderr, "WARNING: This will permanently delete invitation %q.\n", args[0])
				fmt.Fprintf(os.Stderr, "Run with --force to confirm.\n")
				return fmt.Errorf("deleting invitation requires --force flag")
			}
			t, err := getTenant()
			if err != nil {
				return err
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			if err := c.Delete(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/invitations/"+url.PathEscape(args[0]), nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Invitation %s deleted.\n", args[0])
			return nil
		},
	}
	deleteInvitationCmd.Flags().BoolVar(&forceDeleteInvitation, "force", false, "Confirm deletion")
	cmd.AddCommand(deleteInvitationCmd)

	cmd.AddCommand(&cobra.Command{
		Use: "resend <id>", Short: "Resend an invitation email", Args: cobra.ExactArgs(1),
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
			if err := c.Post(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/invitations/"+url.PathEscape(args[0])+"/resend", nil, &result); err != nil {
				return err
			}
			if result != nil {
				prettyPrint(result, outputFmt())
			} else {
				fmt.Fprintln(os.Stderr, "Invitation resent.")
			}
			return nil
		},
	})

	return cmd
}
