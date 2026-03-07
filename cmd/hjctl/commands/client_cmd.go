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

// NewClientCmd creates the `client` command group (OAuth clients).
func NewClientCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "client",
		Aliases: []string{"clients"},
		Short:   "Manage OAuth clients (requires --tenant)",
	}

	cmd.AddCommand(newClientListCmd(getClient, outputFmt, getTenant))
	cmd.AddCommand(newClientGetCmd(getClient, outputFmt, getTenant))
	cmd.AddCommand(newClientCreateCmd(getClient, outputFmt, getTenant))
	cmd.AddCommand(newClientDeleteCmd(getClient, getTenant))
	cmd.AddCommand(newClientUpdateCmd(getClient, outputFmt, getTenant))
	cmd.AddCommand(newClientRevokeSecretCmd(getClient, outputFmt, getTenant))

	return cmd
}

func tenantClientsPath(tenant string) string {
	return "/v2/admin/tenants/" + url.PathEscape(tenant) + "/clients"
}

func newClientListCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List OAuth clients",
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
			if err := c.Get(cmd.Context(), tenantClientsPath(t), &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
}

func newClientGetCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "get <client-id>",
		Short: "Get OAuth client details",
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
			if err := c.Get(cmd.Context(), tenantClientsPath(t)+"/"+url.PathEscape(args[0]), &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
}

func newClientCreateCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	var name, clientType string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an OAuth client",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}
			t, err := getTenant()
			if err != nil {
				return err
			}
			body := map[string]string{"name": name}
			if clientType != "" {
				body["type"] = clientType
			}

			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Post(cmd.Context(), tenantClientsPath(t), body, &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Client name (required)")
	cmd.Flags().StringVar(&clientType, "type", "public", "Client type: public or confidential")

	return cmd
}

func newClientDeleteCmd(getClient func() (*client.Client, error), getTenant func() (string, error)) *cobra.Command {
	var force bool
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "delete <client-id>",
		Short: "Delete an OAuth client",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force {
				return fmt.Errorf("this action is irreversible and will break all apps using this client; use --force to confirm")
			}
			if dryRun {
				fmt.Fprintf(os.Stderr, "[DRY RUN] Would delete client %s\n", args[0])
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
			if err := c.Delete(cmd.Context(), tenantClientsPath(t)+"/"+url.PathEscape(args[0]), nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Client %s deleted.\n", args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Confirm deletion (irreversible)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print what would be done without making any changes")
	return cmd
}

func newClientUpdateCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	var name, redirectURIs string

	cmd := &cobra.Command{
		Use:   "update <client-id>",
		Short: "Update an OAuth client",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]interface{}{}
			if name != "" {
				body["name"] = name
			}
			if redirectURIs != "" {
				uris := strings.Split(redirectURIs, ",")
				for i, u := range uris {
					uris[i] = strings.TrimSpace(u)
				}
				body["redirect_uris"] = uris
			}
			if len(body) == 0 {
				return fmt.Errorf("at least one of --name or --redirect-uris must be provided")
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
			if err := c.Put(cmd.Context(), tenantClientsPath(t)+"/"+url.PathEscape(args[0]), body, &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "New client name")
	cmd.Flags().StringVar(&redirectURIs, "redirect-uris", "", "Comma-separated redirect URIs")

	return cmd
}

func newClientRevokeSecretCmd(getClient func() (*client.Client, error), outputFmt func() string, getTenant func() (string, error)) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "revoke-secret <client-id>",
		Short: "Revoke and regenerate a client secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force {
				fmt.Fprintf(os.Stderr, "WARNING: Revoking the client secret will immediately break all applications using client %q.\n", args[0])
				fmt.Fprintf(os.Stderr, "Run with --force to confirm.\n")
				return fmt.Errorf("revoking client secret requires --force flag")
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
			if err := c.Post(cmd.Context(), tenantClientsPath(t)+"/"+url.PathEscape(args[0])+"/revoke-secret", nil, &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Confirm secret revocation")
	return cmd
}
