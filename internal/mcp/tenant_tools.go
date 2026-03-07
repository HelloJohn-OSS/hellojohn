package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerTenantTools(s *server.MCPServer, h *Handler) {
	// hellojohn_list_tenants
	s.AddTool(
		mcp.NewTool("hellojohn_list_tenants",
			mcp.WithDescription("List all tenants in the HelloJohn instance"),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			data, err := h.DoJSON(ctx, http.MethodGet, adminPath("tenants"), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_get_tenant
	s.AddTool(
		mcp.NewTool("hellojohn_get_tenant",
			mcp.WithDescription("Get details of a specific tenant by slug"),
			mcp.WithString("slug", mcp.Required(), mcp.Description("Tenant slug")),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			slug, _ := args["slug"].(string)
			if slug == "" {
				return errResult(errMissing("slug")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodGet, adminPath("tenants", slug), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_create_tenant
	s.AddTool(
		mcp.NewTool("hellojohn_create_tenant",
			mcp.WithDescription("Create a new tenant"),
			mcp.WithString("slug", mcp.Required(), mcp.Description("Unique tenant slug (lowercase, alphanumeric, hyphens)")),
			mcp.WithString("name", mcp.Required(), mcp.Description("Display name for the tenant")),
			mcp.WithString("language", mcp.Description("Tenant language (default: en)"), mcp.DefaultString("en")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			slug, _ := args["slug"].(string)
			name, _ := args["name"].(string)
			if slug == "" || name == "" {
				return errResult(errMissing("slug, name")), nil
			}
			lang, _ := args["language"].(string)
			if lang == "" {
				lang = "en"
			}
			body := map[string]string{"slug": slug, "name": name, "language": lang}
			data, err := h.DoJSON(ctx, http.MethodPost, adminPath("tenants"), body)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_delete_tenant
	s.AddTool(
		mcp.NewTool("hellojohn_delete_tenant",
			mcp.WithDescription("Delete a tenant by slug. This is destructive and cannot be undone."),
			mcp.WithString("slug", mcp.Required(), mcp.Description("Tenant slug to delete")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			slug, _ := args["slug"].(string)
			if slug == "" {
				return errResult(errMissing("slug")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodDelete, adminPath("tenants", slug), nil)
			if err != nil {
				return errResult(err), nil
			}
			if len(data) == 0 {
				return mcp.NewToolResultText("tenant deleted"), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_export_tenant
	s.AddTool(
		mcp.NewTool("hellojohn_export_tenant",
			mcp.WithDescription("Export a tenant's configuration as JSON"),
			mcp.WithString("slug", mcp.Required(), mcp.Description("Tenant slug to export")),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			slug, _ := args["slug"].(string)
			if slug == "" {
				return errResult(errMissing("slug")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodGet, adminPath("tenants", slug, "export"), nil)
			if err != nil {
				return errResult(err), nil
			}
			// Pretty-print the export
			var pretty json.RawMessage
			if json.Unmarshal(data, &pretty) == nil {
				out, err := json.MarshalIndent(pretty, "", "  ")
				if err != nil {
					return errResult(fmt.Errorf("format export: %w", err)), nil
				}
				return mcp.NewToolResultText(string(out)), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_update_tenant
	s.AddTool(
		mcp.NewTool("hellojohn_update_tenant",
			mcp.WithDescription("Update a tenant's display name or language"),
			mcp.WithString("slug", mcp.Required(), mcp.Description("Tenant slug or ID")),
			mcp.WithString("name", mcp.Description("New display name")),
			mcp.WithString("language", mcp.Description("New language code (e.g., en, es)")),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			slug, _ := args["slug"].(string)
			if slug == "" {
				return errResult(errMissing("slug")), nil
			}
			body := map[string]string{}
			if name, _ := args["name"].(string); name != "" {
				body["name"] = name
			}
			if lang, _ := args["language"].(string); lang != "" {
				body["language"] = lang
			}
			if len(body) == 0 {
				return errResult(errMissing("name or language")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodPut, adminPath("tenants", slug), body)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_get_tenant_settings
	s.AddTool(
		mcp.NewTool("hellojohn_get_tenant_settings",
			mcp.WithDescription("Get the settings for a specific tenant"),
			mcp.WithString("slug", mcp.Required(), mcp.Description("Tenant slug or ID")),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithDestructiveHintAnnotation(false),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			slug, _ := args["slug"].(string)
			if slug == "" {
				return errResult(errMissing("slug")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodGet, adminPath("tenants", slug, "settings"), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	// hellojohn_set_tenant_settings
	s.AddTool(
		mcp.NewTool("hellojohn_set_tenant_settings",
			mcp.WithDescription("Update tenant settings. Provide a JSON object with the settings fields to update (e.g., smtp, cache, user_db)."),
			mcp.WithString("slug", mcp.Required(), mcp.Description("Tenant slug or ID")),
			mcp.WithString("settings_json", mcp.Required(), mcp.Description("JSON object with settings fields to update")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			slug, _ := args["slug"].(string)
			settingsJSON, _ := args["settings_json"].(string)
			if slug == "" || settingsJSON == "" {
				return errResult(errMissing("slug, settings_json")), nil
			}
			var body json.RawMessage
			if err := json.Unmarshal([]byte(settingsJSON), &body); err != nil {
				return errResult(fmt.Errorf("invalid JSON in settings_json: %w", err)), nil
			}
			// GET current settings to obtain the ETag required by the backend
			settingsPath := adminPath("tenants", slug, "settings")
			_, etag, err := h.DoJSONGetETag(ctx, settingsPath)
			if err != nil {
				return errResult(fmt.Errorf("fetch current settings (for ETag): %w", err)), nil
			}
			if etag == "" {
				return errResult(fmt.Errorf("server did not return an ETag; cannot update settings")), nil
			}
			data, err := h.DoJSONWithHeaders(ctx, "PUT", settingsPath, map[string]string{"If-Match": etag}, body)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)
}
