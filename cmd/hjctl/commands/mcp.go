package commands

import (
	"fmt"
	"os"
	"sort"

	hjmcp "github.com/dropDatabas3/hellojohn/internal/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

// NewMCPCmd creates the `mcp` command group.
// The getters are only used by non-serve subcommands. MCP serve resolves
// its own config to avoid os.Exit from require* validators.
func NewMCPCmd(getBaseURL func() string, getAPIKey func() string, getTimeout func() int) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "MCP (Model Context Protocol) server for AI agents",
		Long: `Start an MCP server that exposes HelloJohn operations as tools
for AI agents (Claude, etc). Supports stdio (default) and SSE transports.`,
	}

	cmd.AddCommand(newMCPServeCmd(getBaseURL, getAPIKey, getTimeout))
	cmd.AddCommand(newMCPCapabilitiesCmd())

	return cmd
}

func newMCPServeCmd(getBaseURL func() string, getAPIKey func() string, getTimeout func() int) *cobra.Command {
	var port int

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the MCP server (stdio by default, or SSE with --port)",
		Long: `Start an MCP server that exposes HelloJohn admin tools.

By default uses stdio transport (for Claude Desktop, Cursor, etc.).
Use --port to start an SSE HTTP transport instead.

The MCP server always starts even without --base-url or --api-key;
individual tool calls will return errors if the backend is unreachable.

Configuration comes from the global --base-url / --api-key flags, environment
variables (HELLOJOHN_BASE_URL, HELLOJOHN_API_KEY), or the config file.

Example (stdio):
  hjctl mcp serve --base-url http://localhost:8080 --api-key hj_admin_...

Example (SSE):
  hjctl mcp serve --port 9000 --base-url http://localhost:8080 --api-key hj_admin_...`,
		RunE: func(cmd *cobra.Command, args []string) error {
			baseURL := getBaseURL() // reads global --base-url / config file / env
			apiKey := getAPIKey()   // reads global --api-key / config file / env
			timeout := getTimeout()

			if baseURL != "" {
				fmt.Fprintf(os.Stderr, "MCP server: backend=%s\n", baseURL)
			} else {
				fmt.Fprintln(os.Stderr, "MCP server: WARNING — no base URL configured. Tool calls will fail until --base-url is set.")
			}

			h := hjmcp.NewHandler(baseURL, apiKey, timeout)
			s := hjmcp.NewServer(h)

			if port > 0 {
				// SSE transport — bind to localhost only for security
				addr := fmt.Sprintf("127.0.0.1:%d", port)
				fmt.Fprintf(os.Stderr, "Starting MCP SSE server on %s\n", addr)
				sseServer := server.NewSSEServer(s)
				return sseServer.Start(addr)
			}

			// Stdio transport (default)
			stdio := server.NewStdioServer(s)
			return stdio.Listen(cmd.Context(), os.Stdin, os.Stdout)
		},
	}

	cmd.Flags().IntVar(&port, "port", 0, "Start SSE HTTP server on this port instead of stdio")

	return cmd
}

func newMCPCapabilitiesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "capabilities",
		Short: "List all MCP tools available",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Create a handler with a non-zero timeout so the HTTP client does not
			// use infinite timeout when listing tools locally (L-MCP-2).
			// 30s is generous; tool discovery never hits the network.
			h := hjmcp.NewHandler("", "", 30)
			s := hjmcp.NewServer(h)

			tools := s.ListTools()
			fmt.Println("MCP Tools available:")
			fmt.Println()
			names := make([]string, 0, len(tools))
			for name := range tools {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				t := tools[name]
				fmt.Printf("  %-35s %s\n", name, t.Tool.Description)
			}
			fmt.Printf("\nTotal: %d tools\n", len(tools))
			return nil
		},
	}
}
