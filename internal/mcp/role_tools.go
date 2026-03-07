package mcp

import (
	"context"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerRoleTools(s *server.MCPServer, h *Handler) {
	// hellojohn_list_roles
	s.AddTool(
		mcp.NewTool("hellojohn_list_roles",
			mcp.WithDescription("List all RBAC roles in a tenant"),
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
			data, err := h.DoJSON(ctx, http.MethodGet, adminPath("tenants", tenant, "rbac", "roles"), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_get_role
	s.AddTool(
		mcp.NewTool("hellojohn_get_role",
			mcp.WithDescription("Get details of a specific RBAC role"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("name", mcp.Required(), mcp.Description("Role name")),
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
			data, err := h.DoJSON(ctx, http.MethodGet, adminPath("tenants", tenant, "rbac", "roles", name), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_delete_role
	s.AddTool(
		mcp.NewTool("hellojohn_delete_role",
			mcp.WithDescription("Delete an RBAC role from a tenant"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("name", mcp.Required(), mcp.Description("Role name to delete")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			name, _ := args["name"].(string)
			if tenant == "" || name == "" {
				return errResult(errMissing("tenant, name")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodDelete, adminPath("tenants", tenant, "rbac", "roles", name), nil)
			if err != nil {
				return errResult(err), nil
			}
			if len(data) == 0 {
				return mcp.NewToolResultText("role deleted"), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_create_role
	s.AddTool(
		mcp.NewTool("hellojohn_create_role",
			mcp.WithDescription("Create a new RBAC role in a tenant"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("name", mcp.Required(), mcp.Description("Role name (unique identifier)")),
			mcp.WithString("description", mcp.Description("Role description")),
			mcp.WithString("permissions", mcp.Description("Comma-separated initial permissions (e.g., users:read,users:write)")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			name, _ := args["name"].(string)
			if tenant == "" || name == "" {
				return errResult(errMissing("tenant, name")), nil
			}
			body := map[string]interface{}{"name": name}
			if desc, _ := args["description"].(string); desc != "" {
				body["description"] = desc
			}
			if permsStr, _ := args["permissions"].(string); permsStr != "" {
				body["permissions"] = splitAndTrim(permsStr, ",")
			}
			data, err := h.DoJSON(ctx, http.MethodPost, adminPath("tenants", tenant, "rbac", "roles"), body)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_update_role
	s.AddTool(
		mcp.NewTool("hellojohn_update_role",
			mcp.WithDescription("Update an RBAC role's description or permissions"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("name", mcp.Required(), mcp.Description("Role name")),
			mcp.WithString("description", mcp.Description("New description")),
			mcp.WithString("add_permissions", mcp.Description("Comma-separated permissions to add")),
			mcp.WithString("remove_permissions", mcp.Description("Comma-separated permissions to remove")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			name, _ := args["name"].(string)
			if tenant == "" || name == "" {
				return errResult(errMissing("tenant, name")), nil
			}
			body := map[string]interface{}{}
			if desc, _ := args["description"].(string); desc != "" {
				body["description"] = desc
			}
			if addStr, _ := args["add_permissions"].(string); addStr != "" {
				body["add_permissions"] = splitAndTrim(addStr, ",")
			}
			if remStr, _ := args["remove_permissions"].(string); remStr != "" {
				body["remove_permissions"] = splitAndTrim(remStr, ",")
			}
			if len(body) == 0 {
				return errResult(errMissing("description, add_permissions, or remove_permissions")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodPatch, adminPath("tenants", tenant, "rbac", "roles", name), body)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)
}
