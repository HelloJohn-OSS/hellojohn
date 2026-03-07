package mcp

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// NewServer creates a fully configured MCP server with all HelloJohn tools registered.
// The handler bridges each tool call to the HelloJohn HTTP API.
func NewServer(h *Handler) *server.MCPServer {
	s := server.NewMCPServer(
		"hellojohn",
		"0.1.0",
	)

	// Register all tool groups
	registerTenantTools(s, h)
	registerUserTools(s, h)
	registerClientTools(s, h)
	registerAPIKeyTools(s, h)
	registerScopeTools(s, h)
	registerRoleTools(s, h)
	registerSystemTools(s, h)
	registerSessionTools(s, h)
	registerWebhookTools(s, h)

	return s
}

// jsonText is a convenience for returning JSON as MCP text content.
func jsonText(data []byte) *mcp.CallToolResult {
	return mcp.NewToolResultText(string(data))
}

// errResult wraps an error into an MCP error result.
func errResult(err error) *mcp.CallToolResult {
	return mcp.NewToolResultError(err.Error())
}
