package mcp

import (
	"context"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerSessionTools(s *server.MCPServer, h *Handler) {
	// hellojohn_list_sessions
	s.AddTool(
		mcp.NewTool("hellojohn_list_sessions",
			mcp.WithDescription("List active sessions for a tenant"),
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
			data, err := h.DoJSON(ctx, http.MethodGet, adminPath("tenants", tenant, "sessions"), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_revoke_session
	s.AddTool(
		mcp.NewTool("hellojohn_revoke_session",
			mcp.WithDescription("Revoke a specific session by ID"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("session_id", mcp.Required(), mcp.Description("Session ID to revoke")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			sessionID, _ := args["session_id"].(string)
			if tenant == "" || sessionID == "" {
				return errResult(errMissing("tenant, session_id")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodPost, adminPath("tenants", tenant, "sessions", sessionID, "revoke"), nil)
			if err != nil {
				return errResult(err), nil
			}
			if len(data) == 0 {
				return mcp.NewToolResultText("session revoked"), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_revoke_all_sessions
	s.AddTool(
		mcp.NewTool("hellojohn_revoke_all_sessions",
			mcp.WithDescription("Revoke all active sessions for a tenant"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			if tenant == "" {
				return errResult(errMissing("tenant")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodPost, adminPath("tenants", tenant, "sessions", "revoke-all"), nil)
			if err != nil {
				return errResult(err), nil
			}
			if len(data) == 0 {
				return mcp.NewToolResultText("all sessions revoked"), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_revoke_user_sessions
	s.AddTool(
		mcp.NewTool("hellojohn_revoke_user_sessions",
			mcp.WithDescription("Revoke all active sessions for a specific user in a tenant"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("user_id", mcp.Required(), mcp.Description("User UUID whose sessions should be revoked")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			userID, _ := args["user_id"].(string)
			if tenant == "" || userID == "" {
				return errResult(errMissing("tenant, user_id")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodPost, adminPath("tenants", tenant, "sessions", "revoke-by-user"), map[string]any{"user_id": userID})
			if err != nil {
				return errResult(err), nil
			}
			if len(data) == 0 {
				return mcp.NewToolResultText("user sessions revoked"), nil
			}
			return jsonText(data), nil
		},
	)
}
