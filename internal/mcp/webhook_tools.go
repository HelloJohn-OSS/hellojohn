package mcp

import (
	"context"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerWebhookTools(s *server.MCPServer, h *Handler) {
	// hellojohn_list_webhooks
	s.AddTool(
		mcp.NewTool("hellojohn_list_webhooks",
			mcp.WithDescription("List webhook endpoints for a tenant"),
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
			data, err := h.DoJSON(ctx, http.MethodGet, adminPath("tenants", tenant, "webhooks"), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_create_webhook
	s.AddTool(
		mcp.NewTool("hellojohn_create_webhook",
			mcp.WithDescription("Register a new webhook endpoint for a tenant. The signing secret is auto-generated server-side and returned in the response — it is NOT accepted as an input parameter to prevent secret exposure in logs."),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("url", mcp.Required(), mcp.Description("Webhook endpoint URL")),
			mcp.WithString("events", mcp.Description("Comma-separated event types to subscribe to (e.g., user.created,user.deleted)")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			url, _ := args["url"].(string)
			if tenant == "" || url == "" {
				return errResult(errMissing("tenant, url")), nil
			}
			body := map[string]interface{}{"url": url}
			if eventsStr, _ := args["events"].(string); eventsStr != "" {
				body["events"] = splitAndTrim(eventsStr, ",")
			}
			data, err := h.DoJSON(ctx, http.MethodPost, adminPath("tenants", tenant, "webhooks"), body)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_delete_webhook
	s.AddTool(
		mcp.NewTool("hellojohn_delete_webhook",
			mcp.WithDescription("Delete a webhook endpoint"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("webhook_id", mcp.Required(), mcp.Description("Webhook ID to delete")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			webhookID, _ := args["webhook_id"].(string)
			if tenant == "" || webhookID == "" {
				return errResult(errMissing("tenant, webhook_id")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodDelete, adminPath("tenants", tenant, "webhooks", webhookID), nil)
			if err != nil {
				return errResult(err), nil
			}
			if len(data) == 0 {
				return mcp.NewToolResultText("webhook deleted"), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_test_webhook
	s.AddTool(
		mcp.NewTool("hellojohn_test_webhook",
			mcp.WithDescription("Send a test event to a webhook endpoint to verify connectivity"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("webhook_id", mcp.Required(), mcp.Description("Webhook ID to test")),
			mcp.WithReadOnlyHintAnnotation(false),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			webhookID, _ := args["webhook_id"].(string)
			if tenant == "" || webhookID == "" {
				return errResult(errMissing("tenant, webhook_id")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodPost, adminPath("tenants", tenant, "webhooks", webhookID, "test"), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_get_webhook
	s.AddTool(
		mcp.NewTool("hellojohn_get_webhook",
			mcp.WithDescription("Get details of a specific webhook endpoint"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("webhook_id", mcp.Required(), mcp.Description("Webhook ID")),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			webhookID, _ := args["webhook_id"].(string)
			if tenant == "" || webhookID == "" {
				return errResult(errMissing("tenant, webhook_id")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodGet, adminPath("tenants", tenant, "webhooks", webhookID), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_update_webhook
	s.AddTool(
		mcp.NewTool("hellojohn_update_webhook",
			mcp.WithDescription("Update a webhook endpoint's URL, events or enabled state"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithString("webhook_id", mcp.Required(), mcp.Description("Webhook ID")),
			mcp.WithString("url", mcp.Description("New endpoint URL")),
			mcp.WithString("events", mcp.Description("Comma-separated event types to subscribe to")),
			mcp.WithBoolean("enabled", mcp.Description("Whether the webhook is active")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant, _ := args["tenant"].(string)
			webhookID, _ := args["webhook_id"].(string)
			if tenant == "" || webhookID == "" {
				return errResult(errMissing("tenant, webhook_id")), nil
			}
			body := map[string]any{}
			if u, _ := args["url"].(string); u != "" {
				body["url"] = u
			}
			if eventsStr, _ := args["events"].(string); eventsStr != "" {
				body["events"] = splitAndTrim(eventsStr, ",")
			}
			if enabled, ok := args["enabled"].(bool); ok {
				body["enabled"] = enabled
			}
			if len(body) == 0 {
				return errResult(errMissing("url, events, or enabled")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodPatch, adminPath("tenants", tenant, "webhooks", webhookID), body)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)
}
