package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

// NewProviderCmd creates the `provider` command group (stub — not yet implemented).
func NewProviderCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "provider",
		Short: "Manage social login providers (coming soon)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("provider commands are not yet implemented")
		},
	}
	return cmd
}

// NewMailCmd creates the `mail` command group (stub — not yet implemented).
func NewMailCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mail",
		Short: "Manage email templates and settings (coming soon)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("mail commands are not yet implemented")
		},
	}
	return cmd
}

// NewOIDCCmd creates the `oidc` command group (stub — not yet implemented).
func NewOIDCCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "oidc",
		Short: "Manage OIDC configuration (coming soon)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("oidc commands are not yet implemented")
		},
	}
	return cmd
}
