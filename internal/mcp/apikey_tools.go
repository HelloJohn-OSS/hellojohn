package mcp

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerAPIKeyTools(s *server.MCPServer, h *Handler) {
	// hellojohn_list_api_keys
	s.AddTool(
		mcp.NewTool("hellojohn_list_api_keys",
			mcp.WithDescription("List all API keys (without tokens or hashes)"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			data, err := h.DoJSON(ctx, http.MethodGet, adminPath("api-keys"), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_get_api_key
	s.AddTool(
		mcp.NewTool("hellojohn_get_api_key",
			mcp.WithDescription("Get details of a specific API key by ID"),
			mcp.WithString("id", mcp.Required(), mcp.Description("API key UUID")),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			id, _ := args["id"].(string)
			if id == "" {
				return errResult(errMissing("id")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodGet, adminPath("api-keys", id), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_create_api_key
	s.AddTool(
		mcp.NewTool("hellojohn_create_api_key",
			mcp.WithDescription("Create a new API key. The token is returned ONCE — save it immediately."),
			mcp.WithString("name", mcp.Required(), mcp.Description("Descriptive name for the key")),
			mcp.WithString("scope", mcp.Required(), mcp.Description("Key scope: admin, readonly, cloud, or tenant:{slug} (e.g. tenant:acme)")),
			mcp.WithString("expires_in", mcp.Description("Expiration duration (e.g. '24h', '720h'). Omit for no expiration.")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			name, _ := args["name"].(string)
			scope, _ := args["scope"].(string)
			if name == "" || scope == "" {
				return errResult(errMissing("name, scope")), nil
			}
			// Validate scope: must be one of the well-known values or tenant:{slug}
			switch scope {
			case "admin", "readonly", "cloud":
				// valid
			default:
				if !strings.HasPrefix(scope, "tenant:") {
					return errResult(fmt.Errorf("invalid scope %q: must be admin, readonly, cloud, or tenant:{slug}", scope)), nil
				}
			}

			body := map[string]any{"name": name, "scope": scope}
			if expiresIn, ok := args["expires_in"].(string); ok && expiresIn != "" {
				body["expires_in"] = expiresIn
			}

			data, err := h.DoJSON(ctx, http.MethodPost, adminPath("api-keys"), body)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_revoke_api_key
	s.AddTool(
		mcp.NewTool("hellojohn_revoke_api_key",
			mcp.WithDescription("Revoke an API key. This is permanent and cannot be undone."),
			mcp.WithString("id", mcp.Required(), mcp.Description("API key UUID to revoke")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			id, _ := args["id"].(string)
			if id == "" {
				return errResult(errMissing("id")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodDelete, adminPath("api-keys", id), nil)
			if err != nil {
				return errResult(err), nil
			}
			if len(data) == 0 {
				return mcp.NewToolResultText("api key revoked"), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_rotate_api_key
	s.AddTool(
		mcp.NewTool("hellojohn_rotate_api_key",
			mcp.WithDescription("Rotate an API key: revokes the old one and creates a new one. New token shown ONCE."),
			mcp.WithString("id", mcp.Required(), mcp.Description("API key UUID to rotate")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			id, _ := args["id"].(string)
			if id == "" {
				return errResult(errMissing("id")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodPost, adminPath("api-keys", id, "rotate"), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)
}
