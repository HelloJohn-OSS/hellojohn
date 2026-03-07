package commands

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/cmd/hjctl/client"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// NewAPIKeyCmd creates the `api-key` command group.
func NewAPIKeyCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "api-key",
		Aliases: []string{"apikey", "ak"},
		Short:   "Manage API keys",
	}

	cmd.AddCommand(newAPIKeyListCmd(getClient, outputFmt))
	cmd.AddCommand(newAPIKeyCreateCmd(getClient, outputFmt))
	cmd.AddCommand(newAPIKeyGetCmd(getClient, outputFmt))
	cmd.AddCommand(newAPIKeyRevokeCmd(getClient))
	cmd.AddCommand(newAPIKeyRotateCmd(getClient, outputFmt))

	return cmd
}

func newAPIKeyListCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	var page, limit int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all API keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Get(cmd.Context(), "/v2/admin/api-keys"+paginationQuery(page, limit), &result); err != nil {
				return err
			}

			if outputFmt() == "table" {
				var envelope struct {
					Data []struct {
						ID        string `json:"id"`
						Name      string `json:"name"`
						Scope     string `json:"scope"`
						KeyPrefix string `json:"key_prefix"`
						Active    bool   `json:"is_active"`
						CreatedAt string `json:"created_at"`
					} `json:"data"`
				}
				if err := json.Unmarshal(result, &envelope); err != nil {
					// fallback to raw
					os.Stdout.Write(result)
					return nil
				}
				headers := []string{"ID", "NAME", "SCOPE", "PREFIX", "ACTIVE", "CREATED"}
				var rows [][]string
				for _, k := range envelope.Data {
					active := "yes"
					if !k.Active {
						active = "no"
					}
					rows = append(rows, []string{k.ID, k.Name, k.Scope, k.KeyPrefix, active, k.CreatedAt})
				}
				printTable(headers, rows)
				return nil
			}

			// JSON or YAML
			prettyPrint(result, outputFmt())
			return nil
		},
	}
	addPaginationFlags(cmd, &page, &limit)
	return cmd
}

func newAPIKeyCreateCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	var name, scope, expiresIn string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new API key (token shown ONCE)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}

			validScopes := map[string]bool{"admin": true, "readonly": true, "cloud": true}
			if !validScopes[scope] && !strings.HasPrefix(scope, "tenant:") {
				return fmt.Errorf("invalid --scope %q: must be admin, readonly, cloud, or tenant:{slug}", scope)
			}

			body := map[string]string{
				"name":  name,
				"scope": scope,
			}
			if expiresIn != "" {
				if _, err := time.ParseDuration(expiresIn); err != nil {
					return fmt.Errorf("invalid --expires-in value %q: %w", expiresIn, err)
				}
				body["expires_in"] = expiresIn
			}

			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Post(cmd.Context(), "/v2/admin/api-keys", body, &result); err != nil {
				return err
			}

			fmt.Fprintln(os.Stderr, "⚠️  Save this token — you won't be able to see it again!")
			prettyPrint(result, outputFmt())
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "Name for the API key (required)")
	cmd.Flags().StringVar(&scope, "scope", "readonly", "Scope: admin, readonly, cloud, tenant:{slug}")
	cmd.Flags().StringVar(&expiresIn, "expires-in", "", "Expiration duration (e.g., 720h, 30d)")

	return cmd
}

func newAPIKeyGetCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Get details of an API key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Get(cmd.Context(), "/v2/admin/api-keys/"+url.PathEscape(args[0]), &result); err != nil {
				return err
			}
			prettyPrint(result, outputFmt())
			return nil
		},
	}
}

func newAPIKeyRevokeCmd(getClient func() (*client.Client, error)) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke an API key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force {
				fmt.Fprintf(os.Stderr, "WARNING: This will permanently revoke API key %q.\n", args[0])
				fmt.Fprintf(os.Stderr, "Run with --force to confirm: hjctl api-key revoke --force %s\n", args[0])
				return fmt.Errorf("revocation requires --force flag")
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			if err := c.Delete(cmd.Context(), "/v2/admin/api-keys/"+url.PathEscape(args[0]), nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "API key %s revoked.\n", args[0])
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Confirm revocation without interactive prompt")
	return cmd
}

func newAPIKeyRotateCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "rotate <id>",
		Short: "Rotate an API key (invalidates the existing key immediately; new token shown ONCE)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force {
				fmt.Fprintf(os.Stderr, "WARNING: Rotating API key %q will invalidate it immediately.\n", args[0])
				fmt.Fprintf(os.Stderr, "Any service using this key will stop working until reconfigured.\n")
				fmt.Fprintf(os.Stderr, "Run with --force to confirm: hjctl api-key rotate --force %s\n", args[0])
				return fmt.Errorf("rotate requires --force flag")
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Post(cmd.Context(), "/v2/admin/api-keys/"+url.PathEscape(args[0])+"/rotate", nil, &result); err != nil {
				return err
			}

			fmt.Fprintln(os.Stderr, "⚠️  Save this new token — you won't be able to see it again!")
			prettyPrint(result, outputFmt())
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Confirm rotation without interactive prompt")
	return cmd
}

// printTable writes a simple ASCII table.
func printTable(headers []string, rows [][]string) {
	// Use simple formatting for reliability
	if len(rows) == 0 {
		fmt.Println("(no results)")
		return
	}

	// Calculate column widths
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Print header
	for i, h := range headers {
		fmt.Printf("%-*s  ", widths[i], h)
	}
	fmt.Println()

	// Print separator
	for i := range headers {
		for j := 0; j < widths[i]; j++ {
			fmt.Print("-")
		}
		fmt.Print("  ")
	}
	fmt.Println()

	// Print rows
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) {
				fmt.Printf("%-*s  ", widths[i], cell)
			}
		}
		fmt.Println()
	}
}

// prettyPrint outputs data in the specified format.
func prettyPrint(data json.RawMessage, format string) {
	switch format {
	case "yaml":
		var v any
		if err := json.Unmarshal(data, &v); err != nil {
			// Fallback: write raw bytes if JSON parse fails
			os.Stdout.Write(data)
			return
		}
		out, err := marshalYAML(v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] YAML marshal failed: %v — falling back to JSON\n", err)
			break
		}
		os.Stdout.Write(out)
		return
	case "table":
		// Table rendering is only implemented for api-key list.
		// All other commands fall back to JSON with a warning.
		fmt.Fprintln(os.Stderr, "[WARN] --output table is not supported for this command — printing JSON")
	default:
		// json (default)
	}
	// JSON fallback
	var buf json.RawMessage
	if json.Unmarshal(data, &buf) == nil {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(buf)
	} else {
		os.Stdout.Write(data)
	}
}

func marshalYAML(v any) ([]byte, error) {
	return yaml.Marshal(v)
}
