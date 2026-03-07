package mcp

import (
	"context"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerUserTools(s *server.MCPServer, h *Handler) {
	// hellojohn_list_users
	s.AddTool(
		mcp.NewTool("hellojohn_list_users",
			mcp.WithDescription("List all users in a tenant"),
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
			data, err := h.DoJSON(ctx, http.MethodGet, adminPath("tenants", tenant, "users"), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_get_user
	s.AddTool(
		mcp.NewTool("hellojohn_get_user",
			mcp.WithDescription("Get details of a specific user by ID"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("user_id", mcp.Required(), mcp.Description("User UUID")),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			userID, _ := args["user_id"].(string)
			if tenant == "" || userID == "" {
				return errResult(errMissing("tenant, user_id")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodGet, adminPath("tenants", tenant, "users", userID), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_create_user
	s.AddTool(
		mcp.NewTool("hellojohn_create_user",
			mcp.WithDescription("Create a new user in a tenant. The user will need to set their password via the password reset flow."),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("email", mcp.Required(), mcp.Description("User email address")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			email, _ := args["email"].(string)
			if tenant == "" || email == "" {
				return errResult(errMissing("tenant, email")), nil
			}
			body := map[string]any{"email": email}
			data, err := h.DoJSON(ctx, http.MethodPost, adminPath("tenants", tenant, "users"), body)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_delete_user
	s.AddTool(
		mcp.NewTool("hellojohn_delete_user",
			mcp.WithDescription("Delete a user from a tenant. This is destructive."),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("user_id", mcp.Required(), mcp.Description("User UUID to delete")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			userID, _ := args["user_id"].(string)
			if tenant == "" || userID == "" {
				return errResult(errMissing("tenant, user_id")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodDelete, adminPath("tenants", tenant, "users", userID), nil)
			if err != nil {
				return errResult(err), nil
			}
			if len(data) == 0 {
				return mcp.NewToolResultText("user deleted"), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_update_user
	s.AddTool(
		mcp.NewTool("hellojohn_update_user",
			mcp.WithDescription("Update a user's name or email address"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("user_id", mcp.Required(), mcp.Description("User UUID")),
			mcp.WithString("name", mcp.Description("New display name")),
			mcp.WithString("email", mcp.Description("New email address")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			userID, _ := args["user_id"].(string)
			if tenant == "" || userID == "" {
				return errResult(errMissing("tenant, user_id")), nil
			}
			body := map[string]any{}
			if name, _ := args["name"].(string); name != "" {
				body["name"] = name
			}
			if email, _ := args["email"].(string); email != "" {
				body["email"] = email
			}
			if len(body) == 0 {
				return errResult(errMissing("name or email")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodPatch, adminPath("tenants", tenant, "users", userID), body)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_disable_user
	s.AddTool(
		mcp.NewTool("hellojohn_disable_user",
			mcp.WithDescription("Disable a user account in a tenant"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("user_id", mcp.Required(), mcp.Description("User UUID")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			userID, _ := args["user_id"].(string)
			if tenant == "" || userID == "" {
				return errResult(errMissing("tenant, user_id")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodPost, adminPath("tenants", tenant, "users", userID, "disable"), nil)
			if err != nil {
				return errResult(err), nil
			}
			if len(data) == 0 {
				return mcp.NewToolResultText("user disabled"), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_enable_user
	s.AddTool(
		mcp.NewTool("hellojohn_enable_user",
			mcp.WithDescription("Enable a disabled user account in a tenant"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("user_id", mcp.Required(), mcp.Description("User UUID")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			userID, _ := args["user_id"].(string)
			if tenant == "" || userID == "" {
				return errResult(errMissing("tenant, user_id")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodPost, adminPath("tenants", tenant, "users", userID, "enable"), nil)
			if err != nil {
				return errResult(err), nil
			}
			if len(data) == 0 {
				return mcp.NewToolResultText("user enabled"), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_send_password_reset
	s.AddTool(
		mcp.NewTool("hellojohn_send_password_reset",
			mcp.WithDescription("Send a password reset email to a user. This is the secure way to change passwords - the user receives a link and sets their own password without the password passing through this channel."),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("user_id", mcp.Required(), mcp.Description("User UUID")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			userID, _ := args["user_id"].(string)
			if tenant == "" || userID == "" {
				return errResult(errMissing("tenant, user_id")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodPost, adminPath("tenants", tenant, "users", userID, "password-reset"), nil)
			if err != nil {
				return errResult(err), nil
			}
			if len(data) == 0 {
				return mcp.NewToolResultText("password reset email sent"), nil
			}
			return jsonText(data), nil
		},
	)
}
