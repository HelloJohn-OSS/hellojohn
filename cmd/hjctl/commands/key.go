package commands

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"github.com/dropDatabas3/hellojohn/cmd/hjctl/client"
	"github.com/spf13/cobra"
)

// NewKeyCmd creates the `key` command group (JWT signing keys).
func NewKeyCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "key",
		Aliases: []string{"keys"},
		Short:   "Manage JWT signing keys (requires --tenant)",
	}

	cmd.AddCommand(&cobra.Command{
		Use: "list", Short: "List signing keys",
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
			if err := c.Get(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/keys", &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	})

	var forceRotate bool
	rotateCmd := &cobra.Command{
		Use: "rotate", Short: "Trigger key rotation for a tenant (CAUTION: logs out all users)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !forceRotate {
				fmt.Fprintln(os.Stderr, "WARNING: Key rotation will invalidate ALL active tokens for the tenant, logging out all users.")
				fmt.Fprintln(os.Stderr, "Run with --force to confirm: hjctl key rotate --force")
				return fmt.Errorf("key rotation requires --force flag")
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
			if err := c.Post(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(t)+"/keys/rotate", nil, &result); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "Key rotation triggered.")
			prettyPrint(result, outputFmt())
			return nil
		},
	}
	rotateCmd.Flags().BoolVar(&forceRotate, "force", false, "Confirm key rotation (invalidates ALL active tokens for this tenant)")
	cmd.AddCommand(rotateCmd)

	return cmd
}
