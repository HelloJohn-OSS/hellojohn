package mcp

import (
	"context"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerScopeTools(s *server.MCPServer, h *Handler) {
	// hellojohn_list_scopes
	s.AddTool(
		mcp.NewTool("hellojohn_list_scopes",
			mcp.WithDescription("List all OAuth scopes in a tenant"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			if tenant == "" {
				return errResult(errMissing("tenant")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodGet, adminPath("tenants", tenant, "scopes"), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_create_scope
	s.AddTool(
		mcp.NewTool("hellojohn_create_scope",
			mcp.WithDescription("Create a new OAuth scope in a tenant"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("name", mcp.Required(), mcp.Description("Scope name (e.g. 'read:users')")),
			mcp.WithString("description", mcp.Description("Human-readable description of the scope")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			name, _ := args["name"].(string)
			if tenant == "" || name == "" {
				return errResult(errMissing("tenant, name")), nil
			}
			body := map[string]any{"name": name}
			if desc, ok := args["description"].(string); ok && desc != "" {
				body["description"] = desc
			}
			data, err := h.DoJSON(ctx, http.MethodPost, adminPath("tenants", tenant, "scopes"), body)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_delete_scope
	s.AddTool(
		mcp.NewTool("hellojohn_delete_scope",
			mcp.WithDescription("Delete an OAuth scope from a tenant"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("name", mcp.Required(), mcp.Description("Scope name to delete")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			name, _ := args["name"].(string)
			if tenant == "" || name == "" {
				return errResult(errMissing("tenant, name")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodDelete, adminPath("tenants", tenant, "scopes", name), nil)
			if err != nil {
				return errResult(err), nil
			}
			if len(data) == 0 {
				return mcp.NewToolResultText("scope deleted"), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_get_scope
	s.AddTool(
		mcp.NewTool("hellojohn_get_scope",
			mcp.WithDescription("Get details of a specific OAuth scope"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("name", mcp.Required(), mcp.Description("Scope name")),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			name, _ := args["name"].(string)
			if tenant == "" || name == "" {
				return errResult(errMissing("tenant, name")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodGet, adminPath("tenants", tenant, "scopes", name), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_update_scope
	s.AddTool(
		mcp.NewTool("hellojohn_update_scope",
			mcp.WithDescription("Update an OAuth scope's description"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("name", mcp.Required(), mcp.Description("Scope name")),
			mcp.WithString("description", mcp.Required(), mcp.Description("New description")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			name, _ := args["name"].(string)
			desc, _ := args["description"].(string)
			if tenant == "" || name == "" || desc == "" {
				return errResult(errMissing("tenant, name, description")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodPatch, adminPath("tenants", tenant, "scopes", name), map[string]any{"description": desc})
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)
}
