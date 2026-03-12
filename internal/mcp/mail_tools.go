package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerMailTools(s *server.MCPServer, h *Handler) {
	s.AddTool(
		mcp.NewTool("mail_get_provider",
			mcp.WithDescription("Get email provider configuration for a tenant"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug or ID")),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant := strings.TrimSpace(stringArg(args, "tenant"))
			if tenant == "" {
				return errResult(errMissing("tenant")), nil
			}
			data, err := h.DoJSON(ctx, http.MethodGet, adminPath("tenants", tenant, "settings"), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	s.AddTool(
		mcp.NewTool("mail_set_provider",
			mcp.WithDescription("Configure email provider for a tenant"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug or ID")),
			mcp.WithString("provider", mcp.Required(), mcp.Description("smtp|resend|sendgrid|mailgun")),
			mcp.WithString("from_email", mcp.Required(), mcp.Description("From email")),
			mcp.WithString("api_key", mcp.Description("Provider API key, write-only")),
			mcp.WithString("reply_to", mcp.Description("Reply-To email")),
			mcp.WithString("domain", mcp.Description("Domain (mailgun required)")),
			mcp.WithString("region", mcp.Description("Region us|eu")),
			mcp.WithString("smtp_host", mcp.Description("SMTP host")),
			mcp.WithNumber("smtp_port", mcp.Description("SMTP port")),
			mcp.WithString("smtp_user", mcp.Description("SMTP username")),
			mcp.WithString("smtp_password", mcp.Description("SMTP password")),
			mcp.WithBoolean("smtp_tls", mcp.Description("SMTP TLS")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant := strings.TrimSpace(stringArg(args, "tenant"))
			provider := strings.ToLower(strings.TrimSpace(stringArg(args, "provider")))
			fromEmail := strings.TrimSpace(stringArg(args, "from_email"))
			if tenant == "" || provider == "" || fromEmail == "" {
				return errResult(errMissing("tenant, provider, from_email")), nil
			}
			if !isMailProvider(provider) {
				return errResult(fmt.Errorf("invalid provider: %s", provider)), nil
			}

			path := adminPath("tenants", tenant, "settings")
			raw, etag, err := h.DoJSONGetETag(ctx, path)
			if err != nil {
				return errResult(err), nil
			}
			var settings map[string]any
			if err := json.Unmarshal(raw, &settings); err != nil {
				return errResult(err), nil
			}

			providerPayload := buildProviderPayloadFromArgs(args)
			settings["emailProvider"] = providerPayload
			if provider == "smtp" {
				settings["smtp"] = buildLegacySMTPPayloadFromArgs(args)
			}

			resp, err := h.DoJSONWithHeaders(ctx, http.MethodPut, path, map[string]string{"If-Match": etag}, settings)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(resp), nil
		},
	)

	s.AddTool(
		mcp.NewTool("mail_test",
			mcp.WithDescription("Send a tenant test email"),
			mcp.WithString("tenant", mcp.Required(), mcp.Description("Tenant slug or ID")),
			mcp.WithString("to", mcp.Required(), mcp.Description("Destination email")),
			mcp.WithString("provider", mcp.Description("Optional provider override")),
			mcp.WithString("from_email", mcp.Description("Override from email")),
			mcp.WithString("api_key", mcp.Description("Override API key")),
			mcp.WithString("domain", mcp.Description("Override domain")),
			mcp.WithString("region", mcp.Description("Override region")),
			mcp.WithString("smtp_host", mcp.Description("Override SMTP host")),
			mcp.WithNumber("smtp_port", mcp.Description("Override SMTP port")),
			mcp.WithString("smtp_user", mcp.Description("Override SMTP user")),
			mcp.WithString("smtp_password", mcp.Description("Override SMTP password")),
			mcp.WithBoolean("smtp_tls", mcp.Description("Override SMTP TLS")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			tenant := strings.TrimSpace(stringArg(args, "tenant"))
			to := strings.TrimSpace(stringArg(args, "to"))
			if tenant == "" || to == "" {
				return errResult(errMissing("tenant, to")), nil
			}
			payload := map[string]any{"to": to}
			provider := strings.ToLower(strings.TrimSpace(stringArg(args, "provider")))
			if provider != "" {
				payload["provider"] = buildTestProviderPayloadFromArgs(args)
				if provider == "smtp" {
					payload["smtp"] = buildMailingSMTPOverrideFromArgs(args)
				}
			}
			data, err := h.DoJSON(ctx, http.MethodPost, adminPath("tenants", tenant, "mailing", "test"), payload)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	s.AddTool(
		mcp.NewTool("system_mail_get",
			mcp.WithDescription("Get global system email provider configuration"),
			mcp.WithReadOnlyHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			data, err := h.DoJSON(ctx, http.MethodGet, adminPath("system", "email"), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	s.AddTool(
		mcp.NewTool("system_mail_set",
			mcp.WithDescription("Configure global system email provider"),
			mcp.WithString("provider", mcp.Required(), mcp.Description("smtp|resend|sendgrid|mailgun")),
			mcp.WithString("from_email", mcp.Required(), mcp.Description("From email")),
			mcp.WithString("api_key", mcp.Description("Provider API key")),
			mcp.WithString("reply_to", mcp.Description("Reply-To email")),
			mcp.WithString("domain", mcp.Description("Domain")),
			mcp.WithString("region", mcp.Description("Region")),
			mcp.WithString("smtp_host", mcp.Description("SMTP host")),
			mcp.WithNumber("smtp_port", mcp.Description("SMTP port")),
			mcp.WithString("smtp_user", mcp.Description("SMTP username")),
			mcp.WithString("smtp_password", mcp.Description("SMTP password")),
			mcp.WithBoolean("smtp_tls", mcp.Description("SMTP TLS")),
			mcp.WithDestructiveHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			provider := strings.ToLower(strings.TrimSpace(stringArg(args, "provider")))
			fromEmail := strings.TrimSpace(stringArg(args, "from_email"))
			if provider == "" || fromEmail == "" {
				return errResult(errMissing("provider, from_email")), nil
			}
			if !isMailProvider(provider) {
				return errResult(fmt.Errorf("invalid provider: %s", provider)), nil
			}
			data, err := h.DoJSON(ctx, http.MethodPut, adminPath("system", "email"), buildProviderPayloadFromArgs(args))
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	s.AddTool(
		mcp.NewTool("system_mail_delete",
			mcp.WithDescription("Delete global system email provider"),
			mcp.WithDestructiveHintAnnotation(true),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			data, err := h.DoJSON(ctx, http.MethodDelete, adminPath("system", "email"), nil)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)

	s.AddTool(
		mcp.NewTool("system_mail_test",
			mcp.WithDescription("Send test email using global system provider"),
			mcp.WithString("to", mcp.Required(), mcp.Description("Destination email")),
			mcp.WithString("provider", mcp.Description("Optional provider override")),
			mcp.WithString("from_email", mcp.Description("Override from email")),
			mcp.WithString("api_key", mcp.Description("Override API key")),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			args := req.GetArguments()
			to := strings.TrimSpace(stringArg(args, "to"))
			if to == "" {
				return errResult(errMissing("to")), nil
			}
			payload := map[string]any{"to": to}
			if strings.TrimSpace(stringArg(args, "provider")) != "" {
				payload["provider"] = buildProviderPayloadFromArgs(args)
			}
			data, err := h.DoJSON(ctx, http.MethodPost, adminPath("system", "email", "test"), payload)
			if err != nil {
				return errResult(err), nil
			}
			return jsonText(data), nil
		},
	)
}

func buildProviderPayloadFromArgs(args map[string]any) map[string]any {
	provider := strings.ToLower(strings.TrimSpace(stringArg(args, "provider")))
	payload := map[string]any{
		"provider":  provider,
		"fromEmail": strings.TrimSpace(stringArg(args, "from_email")),
	}
	if v := strings.TrimSpace(stringArg(args, "reply_to")); v != "" {
		payload["replyTo"] = v
	}
	if v := strings.TrimSpace(stringArg(args, "api_key")); v != "" {
		payload["apiKey"] = v
	}
	if v := strings.TrimSpace(stringArg(args, "domain")); v != "" {
		payload["domain"] = v
	}
	if v := strings.TrimSpace(stringArg(args, "region")); v != "" {
		payload["region"] = strings.ToLower(v)
	}
	if v, ok := intArg(args, "timeout_ms"); ok && v > 0 {
		payload["timeoutMs"] = v
	}
	if provider == "smtp" {
		payload["smtpHost"] = strings.TrimSpace(stringArg(args, "smtp_host"))
		if v, ok := intArg(args, "smtp_port"); ok && v > 0 {
			payload["smtpPort"] = v
		}
		if v := strings.TrimSpace(stringArg(args, "smtp_user")); v != "" {
			payload["smtpUsername"] = v
		}
		if v := strings.TrimSpace(stringArg(args, "smtp_password")); v != "" {
			payload["smtpPassword"] = v
		}
		payload["smtpUseTLS"] = boolArg(args, "smtp_tls", true)
	}
	return payload
}

func buildLegacySMTPPayloadFromArgs(args map[string]any) map[string]any {
	payload := map[string]any{
		"host":      strings.TrimSpace(stringArg(args, "smtp_host")),
		"port":      intOrDefault(args, "smtp_port", 587),
		"username":  strings.TrimSpace(stringArg(args, "smtp_user")),
		"fromEmail": strings.TrimSpace(stringArg(args, "from_email")),
		"useTLS":    boolArg(args, "smtp_tls", true),
	}
	if v := strings.TrimSpace(stringArg(args, "smtp_password")); v != "" {
		payload["password"] = v
	}
	return payload
}

func buildTestProviderPayloadFromArgs(args map[string]any) map[string]any {
	payload := map[string]any{
		"kind":      strings.ToLower(strings.TrimSpace(stringArg(args, "provider"))),
		"fromEmail": strings.TrimSpace(stringArg(args, "from_email")),
	}
	if v := strings.TrimSpace(stringArg(args, "api_key")); v != "" {
		payload["apiKey"] = v
	}
	if v := strings.TrimSpace(stringArg(args, "domain")); v != "" {
		payload["domain"] = v
	}
	if v := strings.TrimSpace(stringArg(args, "region")); v != "" {
		payload["region"] = strings.ToLower(v)
	}
	return payload
}

func buildMailingSMTPOverrideFromArgs(args map[string]any) map[string]any {
	payload := map[string]any{
		"host":      strings.TrimSpace(stringArg(args, "smtp_host")),
		"port":      intOrDefault(args, "smtp_port", 587),
		"username":  strings.TrimSpace(stringArg(args, "smtp_user")),
		"fromEmail": strings.TrimSpace(stringArg(args, "from_email")),
		"useTLS":    boolArg(args, "smtp_tls", true),
	}
	if v := strings.TrimSpace(stringArg(args, "smtp_password")); v != "" {
		payload["password"] = v
	}
	return payload
}

func stringArg(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return v
}

func intArg(args map[string]any, key string) (int, bool) {
	switch v := args[key].(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	default:
		return 0, false
	}
}

func intOrDefault(args map[string]any, key string, def int) int {
	if v, ok := intArg(args, key); ok {
		return v
	}
	return def
}

func boolArg(args map[string]any, key string, def bool) bool {
	v, ok := args[key].(bool)
	if !ok {
		return def
	}
	return v
}

func isMailProvider(provider string) bool {
	switch provider {
	case "smtp", "resend", "sendgrid", "mailgun":
		return true
	default:
		return false
	}
}
