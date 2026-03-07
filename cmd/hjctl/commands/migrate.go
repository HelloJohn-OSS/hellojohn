package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/cmd/hjctl/client"
	"github.com/spf13/cobra"
)

// NewMigrateCmd creates the `migrate` command group for ETL migrations.
func NewMigrateCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "migrate",
		Aliases: []string{"migration"},
		Short:   "Manage ETL data migrations for tenants",
		Long: `Start and monitor asynchronous data migrations between tenant databases.

ETL migrations copy user data (users, tokens, MFA, consents, roles, etc.)
from a source database to a target database asynchronously.

Examples:
  # migrate tenant — copy full tenant dataset to a new database
  hjctl migrate tenant --tenant acme --to "postgres://user:pass@host:5432/newdb"

  # migrate users — copy only user accounts for a tenant
  hjctl migrate users --tenant acme --to "postgres://user:pass@host:5432/newdb"

  # cross-instance migration with API keys
  hjctl migrate tenant --tenant acme --from "https://auth.old.com" --to "https://auth.new.com" \
    --api-key-from OLD_KEY --api-key-to NEW_KEY

  # preview without making changes
  hjctl migrate tenant --tenant acme --to "postgres://..." --dry-run

  # list / inspect jobs
  hjctl migrate list acme
  hjctl migrate get acme <job-id>`,
	}

	cmd.AddCommand(newMigrateTenantCmd(getClient, outputFmt))
	cmd.AddCommand(newMigrateUsersCmd(getClient, outputFmt))
	cmd.AddCommand(newMigrateListCmd(getClient, outputFmt))
	cmd.AddCommand(newMigrateGetCmd(getClient, outputFmt))

	return cmd
}

// newMigrateTenantCmd — hjctl migrate tenant: copies all tenant data to a new database.
func newMigrateTenantCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	var tenant, fromURL, toURL, driver, apiKeyFrom, apiKeyTo string
	var dryRun, watch bool

	cmd := &cobra.Command{
		Use:   "tenant",
		Short: "Migrate all data for a tenant to a new database",
		Long: `Copy all tenant data (users, tokens, MFA, consents, roles) to a target database.

The migration runs asynchronously on the server. Use --watch to poll progress until completion.

Examples:
  hjctl migrate tenant --tenant acme --to "postgres://user:pass@host:5432/newdb"
  hjctl migrate tenant --tenant acme --from "postgres://old" --to "postgres://new" --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if dryRun {
				fmt.Printf("[dry-run] Would migrate tenant %q from %q to %q (driver: %s)\n",
					tenant, fromURL, toURL, driver)
				return nil
			}

			c, err := getClient()
			if err != nil {
				return err
			}

			body := map[string]string{
				"dsn":          toURL,
				"driver":       driver,
				"api_key_from": apiKeyFrom,
				"api_key_to":   apiKeyTo,
			}

			var result json.RawMessage
			if err := c.Post(cmd.Context(), fmt.Sprintf("/v2/admin/tenants/%s/etl-migrate", tenant), body, &result); err != nil {
				return err
			}

			prettyPrint(result, outputFmt())

			if watch {
				var job struct {
					JobID string `json:"job_id"`
					ID    string `json:"id"`
				}
				if jsonErr := json.Unmarshal(result, &job); jsonErr != nil {
					fmt.Println("Warning: could not parse job ID from response, skipping watch mode")
					return nil
				}
				jobID := strings.TrimSpace(job.JobID)
				if jobID == "" {
					jobID = strings.TrimSpace(job.ID)
				}
				if jobID == "" {
					fmt.Println("Warning: could not parse job ID from response, skipping watch mode")
					return nil
				}
				return pollMigrationJob(cmd.Context(), c, tenant, jobID)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&tenant, "tenant", "", "Tenant slug (required)")
	cmd.Flags().StringVar(&fromURL, "from", "", "Source database DSN or instance URL")
	cmd.Flags().StringVar(&toURL, "to", "", "Target database DSN (required)")
	cmd.Flags().StringVar(&driver, "driver", "postgres", "Database driver (postgres|mysql)")
	cmd.Flags().StringVar(&apiKeyFrom, "api-key-from", "", "API key for source instance")
	cmd.Flags().StringVar(&apiKeyTo, "api-key-to", "", "API key for target instance")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview migration without making changes")
	cmd.Flags().BoolVar(&watch, "watch", false, "Poll job status until completion")
	_ = cmd.MarkFlagRequired("tenant")

	return cmd
}

// newMigrateUsersCmd — hjctl migrate users: copies only user accounts for a tenant.
func newMigrateUsersCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	var tenant, fromURL, toURL, driver, apiKeyFrom, apiKeyTo string
	var dryRun, watch bool

	cmd := &cobra.Command{
		Use:   "users",
		Short: "Migrate user accounts for a tenant to a new database",
		Long: `Copy user accounts (and identities) for a tenant to a target database.
This is a targeted migration that only copies the users/identity tables.

Examples:
  hjctl migrate users --tenant acme --to "postgres://user:pass@host:5432/newdb"
  hjctl migrate users --tenant acme --from "postgres://old" --to "postgres://new" --dry-run`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if dryRun {
				fmt.Printf("[dry-run] Would migrate users for tenant %q from %q to %q (driver: %s)\n",
					tenant, fromURL, toURL, driver)
				return nil
			}

			c, err := getClient()
			if err != nil {
				return err
			}

			body := map[string]string{
				"dsn":          toURL,
				"driver":       driver,
				"type":         "users_only",
				"api_key_from": apiKeyFrom,
				"api_key_to":   apiKeyTo,
			}

			var result json.RawMessage
			if err := c.Post(cmd.Context(), fmt.Sprintf("/v2/admin/tenants/%s/etl-migrate", tenant), body, &result); err != nil {
				return err
			}

			prettyPrint(result, outputFmt())

			if watch {
				var job struct {
					JobID string `json:"job_id"`
					ID    string `json:"id"`
				}
				if jsonErr := json.Unmarshal(result, &job); jsonErr != nil {
					fmt.Println("Warning: could not parse job ID from response, skipping watch mode")
					return nil
				}
				jobID := strings.TrimSpace(job.JobID)
				if jobID == "" {
					jobID = strings.TrimSpace(job.ID)
				}
				if jobID == "" {
					fmt.Println("Warning: could not parse job ID from response, skipping watch mode")
					return nil
				}
				return pollMigrationJob(cmd.Context(), c, tenant, jobID)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&tenant, "tenant", "", "Tenant slug (required)")
	cmd.Flags().StringVar(&fromURL, "from", "", "Source database DSN or instance URL")
	cmd.Flags().StringVar(&toURL, "to", "", "Target database DSN (required)")
	cmd.Flags().StringVar(&driver, "driver", "postgres", "Database driver (postgres|mysql)")
	cmd.Flags().StringVar(&apiKeyFrom, "api-key-from", "", "API key for source instance")
	cmd.Flags().StringVar(&apiKeyTo, "api-key-to", "", "API key for target instance")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview migration without making changes")
	cmd.Flags().BoolVar(&watch, "watch", false, "Poll job status until completion")
	_ = cmd.MarkFlagRequired("tenant")

	return cmd
}

func newMigrateListCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list <tenant>",
		Short: "List ETL migration jobs for a tenant",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenant := args[0]
			c, err := getClient()
			if err != nil {
				return err
			}

			var result json.RawMessage
			if err := c.Get(cmd.Context(), fmt.Sprintf("/v2/admin/tenants/%s/etl-migrations", tenant), &result); err != nil {
				return err
			}

			if outputFmt() == "table" {
				var envelope struct {
					Jobs []struct {
						ID          string `json:"id"`
						Type        string `json:"type"`
						Status      string `json:"status"`
						ProgressPct int    `json:"progress_pct"`
						StartedAt   string `json:"started_at"`
					} `json:"jobs"`
				}
				if err := json.Unmarshal(result, &envelope); err != nil {
					prettyPrint(result, "json")
					return nil
				}
				headers := []string{"ID", "TYPE", "STATUS", "PROGRESS", "STARTED"}
				var rows [][]string
				for _, j := range envelope.Jobs {
					rows = append(rows, []string{
						j.ID, j.Type, j.Status,
						fmt.Sprintf("%d%%", j.ProgressPct),
						j.StartedAt,
					})
				}
				printTable(headers, rows)
				return nil
			}

			prettyPrint(result, outputFmt())
			return nil
		},
	}
	return cmd
}

func newMigrateGetCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <tenant> <job-id>",
		Short: "Get details of a specific ETL migration job",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenant, jobID := args[0], args[1]
			c, err := getClient()
			if err != nil {
				return err
			}

			var result json.RawMessage
			if err := c.Get(cmd.Context(), fmt.Sprintf("/v2/admin/tenants/%s/etl-migrations/%s", tenant, jobID), &result); err != nil {
				return err
			}

			prettyPrint(result, outputFmt())
			return nil
		},
	}
	return cmd
}

// pollMigrationJob polls a migration job every 5 seconds until it completes or fails.
func pollMigrationJob(ctx context.Context, c *client.Client, tenant, jobID string) error {
	fmt.Printf("Watching job %s ...\n", jobID)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			var job struct {
				Status      string `json:"status"`
				ProgressPct int    `json:"progress_pct"`
				Error       string `json:"error,omitempty"`
			}
			if err := c.Get(ctx, fmt.Sprintf("/v2/admin/tenants/%s/etl-migrations/%s", tenant, jobID), &job); err != nil {
				fmt.Printf("Poll error: %v\n", err)
				continue
			}

			fmt.Printf("  Status: %-12s  Progress: %d%%\n", job.Status, job.ProgressPct)

			switch job.Status {
			case "completed":
				fmt.Println("Migration completed successfully.")
				return nil
			case "failed":
				return fmt.Errorf("migration failed: %s", job.Error)
			}
		}
	}
}
