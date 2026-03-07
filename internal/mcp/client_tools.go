package mcp

import (
	"context"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerClientTools(s *server.MCPServer, h *Handler) {
	// hellojohn_list_clients
	s.AddTool(
		mcp.NewTool("hellojohn_list_clients",
			mcp.WithDescription("List all OAuth clients in a tenant"),
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
			data, err := h.DoJSON(ctx, http.MethodGet, adminPath("tenants", tenant, "clients"), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_get_client
	s.AddTool(
		mcp.NewTool("hellojohn_get_client",
			mcp.WithDescription("Get details of a specific OAuth client"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("client_id", mcp.Required(), mcp.Description("Client ID")),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			clientID, _ := args["client_id"].(string)
			if tenant == "" || clientID == "" {
				return errResult(errMissing("tenant, client_id")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodGet, adminPath("tenants", tenant, "clients", clientID), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_create_client
	s.AddTool(
		mcp.NewTool("hellojohn_create_client",
			mcp.WithDescription("Create a new OAuth client in a tenant"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("name", mcp.Required(), mcp.Description("Client display name")),
			mcp.WithString("client_id", mcp.Required(), mcp.Description("Unique client identifier (e.g. myapp_web)")),
			mcp.WithString("type", mcp.Description("Client type: public or confidential"), mcp.DefaultString("public")),
			mcp.WithString("redirect_uris", mcp.Description("Comma-separated redirect URIs (required unless auth_profile is m2m)")),
			mcp.WithString("auth_profile", mcp.Description("Auth profile: spa, web, m2m, native")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			name, _ := args["name"].(string)
			clientID, _ := args["client_id"].(string)
			if tenant == "" || name == "" || clientID == "" {
				return errResult(errMissing("tenant, name, client_id")), nil
			}
			clientType, _ := args["type"].(string)
			if clientType == "" {
				clientType = "public"
			}
			body := map[string]any{"name": name, "client_id": clientID, "type": clientType}
			if urisStr, _ := args["redirect_uris"].(string); urisStr != "" {
				body["redirect_uris"] = splitAndTrim(urisStr, ",")
			}
			if profile, _ := args["auth_profile"].(string); profile != "" {
				body["auth_profile"] = profile
			}
			data, err := h.DoJSON(ctx, http.MethodPost, adminPath("tenants", tenant, "clients"), body)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_delete_client
	s.AddTool(
		mcp.NewTool("hellojohn_delete_client",
			mcp.WithDescription("Delete an OAuth client from a tenant"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("client_id", mcp.Required(), mcp.Description("Client ID to delete")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			clientID, _ := args["client_id"].(string)
			if tenant == "" || clientID == "" {
				return errResult(errMissing("tenant, client_id")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodDelete, adminPath("tenants", tenant, "clients", clientID), nil)
			if err != nil {
				return errResult(err), nil
			}
			if len(data) == 0 {
				return mcp.NewToolResultText("client deleted"), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_update_client
	s.AddTool(
		mcp.NewTool("hellojohn_update_client",
			mcp.WithDescription("Update an OAuth client's name or redirect URIs"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("client_id", mcp.Required(), mcp.Description("Client ID")),
			mcp.WithString("name", mcp.Description("New client name")),
			mcp.WithString("redirect_uris", mcp.Description("Comma-separated redirect URIs")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			clientID, _ := args["client_id"].(string)
			if tenant == "" || clientID == "" {
				return errResult(errMissing("tenant, client_id")), nil
			}
			body := map[string]interface{}{}
			if name, _ := args["name"].(string); name != "" {
				body["name"] = name
			}
			if urisStr, _ := args["redirect_uris"].(string); urisStr != "" {
				body["redirect_uris"] = splitAndTrim(urisStr, ",")
			}
			if len(body) == 0 {
				return errResult(errMissing("name or redirect_uris")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodPatch, adminPath("tenants", tenant, "clients", clientID), body)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_revoke_client_secret
	s.AddTool(
		mcp.NewTool("hellojohn_revoke_client_secret",
			mcp.WithDescription("Revoke the current client secret and generate a new one"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("client_id", mcp.Required(), mcp.Description("Client ID")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			clientID, _ := args["client_id"].(string)
			if tenant == "" || clientID == "" {
				return errResult(errMissing("tenant, client_id")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodPost, adminPath("tenants", tenant, "clients", clientID, "revoke-secret"), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)
}
