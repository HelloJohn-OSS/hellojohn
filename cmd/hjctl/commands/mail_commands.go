package commands

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/dropDatabas3/hellojohn/cmd/hjctl/client"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type emailProviderFlags struct {
	provider   string
	fromEmail  string
	replyTo    string
	apiKey     string
	apiPrompt  bool
	domain     string
	region     string
	timeoutMs  int
	smtpHost   string
	smtpPort   int
	smtpUser   string
	smtpPass   string
	smtpPrompt bool
	smtpTLS    bool
}

func newMailCommandGroup(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mail",
		Short: "Manage tenant email providers and templates",
	}

	cmd.AddCommand(
		newMailGetProviderCmd(getClient, outputFmt),
		newMailSetProviderCmd(getClient),
		newMailTestCmd(getClient),
		newMailGetTemplateCmd(getClient, outputFmt),
		newMailSetTemplateCmd(getClient),
	)

	return cmd
}

func newMailGetProviderCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	return &cobra.Command{
		Use:   "get-provider <tenant>",
		Short: "Show email provider configuration for a tenant",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenant := args[0]
			c, err := getClient()
			if err != nil {
				return err
			}

			settings, _, err := fetchTenantSettings(cmd.Context(), c, tenant)
			if err != nil {
				return err
			}

			ep, _ := asMap(settings["emailProvider"])
			if ep != nil && toStr(ep["provider"]) != "" {
				if outputFmt() != "table" {
					out, _ := json.Marshal(ep)
					prettyPrint(out, outputFmt())
					return nil
				}
				fmt.Printf("Provider:    %s\n", toStr(ep["provider"]))
				fmt.Printf("From:        %s\n", toStr(ep["fromEmail"]))
				fmt.Printf("Reply-To:    %s\n", orDash(toStr(ep["replyTo"])))
				fmt.Printf("Domain:      %s\n", orDash(toStr(ep["domain"])))
				fmt.Printf("Region:      %s\n", orDash(toStr(ep["region"])))
				if b, ok := ep["apiKeyConfigured"].(bool); ok && b {
					fmt.Println("API Key:     [configured]")
				} else {
					fmt.Println("API Key:     [not set]")
				}
				return nil
			}

			smtp, _ := asMap(settings["smtp"])
			if smtp != nil && toStr(smtp["host"]) != "" {
				if outputFmt() != "table" {
					out, _ := json.Marshal(map[string]any{"provider": "smtp", "smtp": smtp})
					prettyPrint(out, outputFmt())
					return nil
				}
				fmt.Println("Provider:    smtp (legacy)")
				fmt.Printf("Host:        %s\n", toStr(smtp["host"]))
				fmt.Printf("Port:        %d\n", toInt(smtp["port"], 587))
				fmt.Printf("From:        %s\n", coalesce(toStr(smtp["fromEmail"]), toStr(smtp["username"])))
				return nil
			}

			fmt.Println("No email provider configured.")
			return nil
		},
	}
}

func newMailSetProviderCmd(getClient func() (*client.Client, error)) *cobra.Command {
	f := emailProviderFlags{region: "us", timeoutMs: 10000, smtpPort: 587, smtpTLS: true}

	cmd := &cobra.Command{
		Use:   "set-provider <tenant>",
		Short: "Configure email provider for a tenant",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenant := args[0]
			f.provider = strings.ToLower(strings.TrimSpace(f.provider))
			if err := resolvePromptSecrets(&f); err != nil {
				return err
			}
			if !isValidProvider(f.provider) {
				return fmt.Errorf("invalid provider %q (valid: smtp, resend, sendgrid, mailgun)", f.provider)
			}
			if strings.TrimSpace(f.fromEmail) == "" {
				return fmt.Errorf("--from is required")
			}
			if f.provider == "smtp" && strings.TrimSpace(f.smtpHost) == "" {
				return fmt.Errorf("--smtp-host is required for smtp provider")
			}
			if f.provider == "mailgun" && strings.TrimSpace(f.domain) == "" {
				return fmt.Errorf("--domain is required for mailgun provider")
			}

			c, err := getClient()
			if err != nil {
				return err
			}
			settings, etag, err := fetchTenantSettings(cmd.Context(), c, tenant)
			if err != nil {
				return err
			}

			settings["emailProvider"] = buildTenantProviderPayload(f)
			if f.provider == "smtp" {
				settings["smtp"] = buildLegacySMTPPayload(f)
			}

			if err := updateTenantSettings(cmd.Context(), c, tenant, etag, settings); err != nil {
				return err
			}

			fmt.Printf("✓ Email provider configured: %s (from: %s)\n", f.provider, f.fromEmail)
			return nil
		},
	}

	bindProviderFlags(cmd, &f)
	_ = cmd.MarkFlagRequired("provider")
	_ = cmd.MarkFlagRequired("from")
	return cmd
}

func newMailTestCmd(getClient func() (*client.Client, error)) *cobra.Command {
	f := emailProviderFlags{region: "us", timeoutMs: 10000, smtpPort: 587, smtpTLS: true}
	var to string

	cmd := &cobra.Command{
		Use:   "test <tenant>",
		Short: "Send a test email for a tenant",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenant := args[0]
			if strings.TrimSpace(to) == "" {
				return fmt.Errorf("--to is required")
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			payload := map[string]any{"to": strings.TrimSpace(to)}
			if strings.TrimSpace(f.provider) != "" {
				f.provider = strings.ToLower(strings.TrimSpace(f.provider))
				if err := resolvePromptSecrets(&f); err != nil {
					return err
				}
				payload["provider"] = buildTestProviderPayload(f)
				if f.provider == "smtp" {
					payload["smtp"] = buildMailingSMTPOverridePayload(f)
				}
			} else if f.apiPrompt || f.smtpPrompt {
				return fmt.Errorf("--provider is required when using prompt flags")
			}

			var result json.RawMessage
			if err := c.Post(cmd.Context(), "/v2/admin/tenants/"+url.PathEscape(tenant)+"/mailing/test", payload, &result); err != nil {
				return err
			}
			fmt.Printf("✓ Test email sent to %s\n", to)
			return nil
		},
	}

	cmd.Flags().StringVar(&to, "to", "", "Destination email address (required)")
	bindProviderFlags(cmd, &f)
	return cmd
}
func newMailGetTemplateCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	var templateType string

	cmd := &cobra.Command{
		Use:   "get-template <tenant>",
		Short: "Get a tenant email template",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenant := args[0]
			if strings.TrimSpace(templateType) == "" {
				return fmt.Errorf("--type is required")
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			settings, _, err := fetchTenantSettings(cmd.Context(), c, tenant)
			if err != nil {
				return err
			}

			tpl, err := readTemplate(settings, templateType)
			if err != nil {
				return err
			}

			if outputFmt() == "table" {
				fmt.Printf("Subject: %s\n\n%s\n", toStr(tpl["subject"]), toStr(tpl["body"]))
				return nil
			}
			out, _ := json.Marshal(tpl)
			prettyPrint(out, outputFmt())
			return nil
		},
	}

	cmd.Flags().StringVar(&templateType, "type", "", "Template type: verify_email|reset_password|user_blocked|user_unblocked")
	_ = cmd.MarkFlagRequired("type")
	return cmd
}

func newMailSetTemplateCmd(getClient func() (*client.Client, error)) *cobra.Command {
	var templateType string
	var subject string
	var body string
	var bodyFile string

	cmd := &cobra.Command{
		Use:   "set-template <tenant>",
		Short: "Update a tenant email template",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			tenant := args[0]
			if strings.TrimSpace(templateType) == "" {
				return fmt.Errorf("--type is required")
			}
			if bodyFile != "" {
				data, err := os.ReadFile(bodyFile)
				if err != nil {
					return fmt.Errorf("read --body-file: %w", err)
				}
				body = string(data)
			}

			c, err := getClient()
			if err != nil {
				return err
			}
			settings, etag, err := fetchTenantSettings(cmd.Context(), c, tenant)
			if err != nil {
				return err
			}

			currentTpl, _ := readTemplate(settings, templateType)
			if subject == "" {
				subject = toStr(currentTpl["subject"])
			}
			if body == "" {
				body = toStr(currentTpl["body"])
			}
			if subject == "" || body == "" {
				return fmt.Errorf("template requires subject and body (set --subject and --body/--body-file)")
			}

			mailing, _ := asMap(settings["mailing"])
			if mailing == nil {
				mailing = map[string]any{}
			}
			templates, _ := asMap(mailing["templates"])
			if templates == nil {
				templates = map[string]any{}
			}
			templates[templateType] = map[string]any{"subject": subject, "body": body}
			mailing["templates"] = templates
			settings["mailing"] = mailing

			if err := updateTenantSettings(cmd.Context(), c, tenant, etag, settings); err != nil {
				return err
			}

			fmt.Printf("✓ Template updated: %s\n", templateType)
			return nil
		},
	}

	cmd.Flags().StringVar(&templateType, "type", "", "Template type: verify_email|reset_password|user_blocked|user_unblocked")
	cmd.Flags().StringVar(&subject, "subject", "", "Template subject")
	cmd.Flags().StringVar(&body, "body", "", "Template HTML body")
	cmd.Flags().StringVar(&bodyFile, "body-file", "", "Path to HTML file used as template body")
	_ = cmd.MarkFlagRequired("type")
	return cmd
}

// NewSystemMailCmd creates `hjctl system mail`.
func NewSystemMailCmd(getClient func() (*client.Client, error), outputFmt func() string) *cobra.Command {
	f := emailProviderFlags{region: "us", timeoutMs: 10000, smtpPort: 587, smtpTLS: true}
	var to string
	var yes bool

	cmd := &cobra.Command{
		Use:   "mail",
		Short: "Manage global system email provider",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "get",
		Short: "Get global system email provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Get(cmd.Context(), "/v2/admin/system/email", &result); err != nil {
				return err
			}
			if err := printSystemMailStatus(result); err != nil {
				if outputFmt() == "table" {
					return err
				}
				prettyPrint(result, outputFmt())
				return nil
			}
			if outputFmt() == "json" || outputFmt() == "yaml" {
				fmt.Println()
				prettyPrint(result, outputFmt())
			}
			return nil
		},
	})

	setCmd := &cobra.Command{
		Use:   "set",
		Short: "Set global system email provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			f.provider = strings.ToLower(strings.TrimSpace(f.provider))
			if err := resolvePromptSecrets(&f); err != nil {
				return err
			}
			if !isValidProvider(f.provider) {
				return fmt.Errorf("invalid provider %q", f.provider)
			}
			if strings.TrimSpace(f.fromEmail) == "" {
				return fmt.Errorf("--from is required")
			}
			if f.provider == "smtp" && strings.TrimSpace(f.smtpHost) == "" {
				return fmt.Errorf("--smtp-host is required for smtp provider")
			}
			if f.provider == "mailgun" && strings.TrimSpace(f.domain) == "" {
				return fmt.Errorf("--domain is required for mailgun")
			}

			c, err := getClient()
			if err != nil {
				return err
			}
			var result json.RawMessage
			if err := c.Put(cmd.Context(), "/v2/admin/system/email", buildTenantProviderPayload(f), &result); err != nil {
				return err
			}
			fmt.Printf("✓ Global email provider configured: %s\n", f.provider)
			return nil
		},
	}
	bindProviderFlags(setCmd, &f)
	_ = setCmd.MarkFlagRequired("provider")
	_ = setCmd.MarkFlagRequired("from")
	cmd.AddCommand(setCmd)

	deleteCmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete global system email provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				ok, err := confirmAction("Warning: tenants without own provider will fallback to env vars after this. Confirm? [y/N]: ")
				if err != nil {
					return err
				}
				if !ok {
					fmt.Println("Cancelled.")
					return nil
				}
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			if err := c.Delete(cmd.Context(), "/v2/admin/system/email", nil); err != nil {
				return err
			}
			fmt.Println("✓ Global email provider configuration deleted.")
			return nil
		},
	}
	deleteCmd.Flags().BoolVar(&yes, "yes", false, "Delete without confirmation prompt")
	cmd.AddCommand(deleteCmd)

	testCmd := &cobra.Command{
		Use:   "test",
		Short: "Send test email using global provider",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(to) == "" {
				return fmt.Errorf("--to is required")
			}
			c, err := getClient()
			if err != nil {
				return err
			}
			payload := map[string]any{"to": strings.TrimSpace(to)}
			if strings.TrimSpace(f.provider) != "" {
				f.provider = strings.ToLower(strings.TrimSpace(f.provider))
				if err := resolvePromptSecrets(&f); err != nil {
					return err
				}
				payload["provider"] = buildTenantProviderPayload(f)
			} else if f.apiPrompt || f.smtpPrompt {
				return fmt.Errorf("--provider is required when using prompt flags")
			}
			var result systemMailTestResponse
			if err := c.Post(cmd.Context(), "/v2/admin/system/email/test", payload, &result); err != nil {
				return err
			}
			provider := strings.TrimSpace(result.Provider)
			if provider == "" {
				provider = strings.TrimSpace(f.provider)
			}
			if provider == "" {
				provider = "active provider"
			}
			fmt.Printf("✓ Test email sent to %s via %s (global provider)\n", to, provider)
			return nil
		},
	}
	testCmd.Flags().StringVar(&to, "to", "", "Destination email (required)")
	bindProviderFlags(testCmd, &f)
	cmd.AddCommand(testCmd)

	return cmd
}

func bindProviderFlags(cmd *cobra.Command, f *emailProviderFlags) {
	cmd.Flags().StringVar(&f.provider, "provider", "", "Provider: smtp|resend|sendgrid|mailgun")
	cmd.Flags().StringVar(&f.fromEmail, "from", "", "From email address")
	cmd.Flags().StringVar(&f.replyTo, "reply-to", "", "Reply-To email address")
	cmd.Flags().StringVar(&f.apiKey, "api-key", "", "Provider API key (write-only)")
	cmd.Flags().BoolVar(&f.apiPrompt, "api-key-prompt", false, "Prompt for provider API key (hidden input)")
	cmd.Flags().StringVar(&f.domain, "domain", "", "Domain (required for mailgun)")
	cmd.Flags().StringVar(&f.region, "region", "us", "Region: us|eu")
	cmd.Flags().IntVar(&f.timeoutMs, "timeout-ms", 10000, "Timeout in milliseconds")
	cmd.Flags().StringVar(&f.smtpHost, "smtp-host", "", "SMTP host")
	cmd.Flags().IntVar(&f.smtpPort, "smtp-port", 587, "SMTP port")
	cmd.Flags().StringVar(&f.smtpUser, "smtp-user", "", "SMTP username")
	cmd.Flags().StringVar(&f.smtpPass, "smtp-password", "", "SMTP password")
	cmd.Flags().BoolVar(&f.smtpPrompt, "smtp-password-prompt", false, "Prompt for SMTP password (hidden input)")
	cmd.Flags().BoolVar(&f.smtpTLS, "smtp-tls", true, "Use TLS for SMTP")
}

func resolvePromptSecrets(f *emailProviderFlags) error {
	provider := strings.ToLower(strings.TrimSpace(f.provider))

	if f.apiPrompt {
		if strings.TrimSpace(f.apiKey) != "" {
			return fmt.Errorf("use either --api-key or --api-key-prompt")
		}
		if provider == "smtp" {
			return fmt.Errorf("--api-key-prompt is not valid for smtp provider")
		}
		secret, err := promptHidden("Enter API key: ")
		if err != nil {
			return fmt.Errorf("read api key: %w", err)
		}
		if secret == "" {
			return fmt.Errorf("api key cannot be empty")
		}
		f.apiKey = secret
	}

	if f.smtpPrompt {
		if strings.TrimSpace(f.smtpPass) != "" {
			return fmt.Errorf("use either --smtp-password or --smtp-password-prompt")
		}
		if provider != "smtp" {
			return fmt.Errorf("--smtp-password-prompt is only valid for smtp provider")
		}
		secret, err := promptHidden("Enter SMTP password: ")
		if err != nil {
			return fmt.Errorf("read smtp password: %w", err)
		}
		if secret == "" {
			return fmt.Errorf("smtp password cannot be empty")
		}
		f.smtpPass = secret
	}

	return nil
}

func promptHidden(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())

	if term.IsTerminal(fd) {
		raw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(raw)), nil
	}

	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	fmt.Fprintln(os.Stderr)
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func confirmAction(prompt string) (bool, error) {
	fmt.Fprint(os.Stderr, prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return false, err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

func fetchTenantSettings(ctx context.Context, c *client.Client, tenant string) (map[string]any, string, error) {
	path := "/v2/admin/tenants/" + url.PathEscape(tenant) + "/settings"
	var settings map[string]any
	etag, err := getJSONWithETag(ctx, c, path, &settings)
	if err != nil {
		return nil, "", err
	}
	return settings, etag, nil
}

func updateTenantSettings(ctx context.Context, c *client.Client, tenant, etag string, settings map[string]any) error {
	path := "/v2/admin/tenants/" + url.PathEscape(tenant) + "/settings"
	var result json.RawMessage
	return putJSONWithIfMatch(ctx, c, path, settings, etag, &result)
}

func getJSONWithETag(ctx context.Context, c *client.Client, path string, out any) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if c.APIKey != "" {
		req.Header.Set("X-API-Key", c.APIKey)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return "", &client.APIError{Status: resp.StatusCode, Message: string(body)}
	}
	if out != nil && len(body) > 0 {
		if err := json.Unmarshal(body, out); err != nil {
			return "", fmt.Errorf("decode response: %w", err)
		}
	}
	return resp.Header.Get("ETag"), nil
}

func putJSONWithIfMatch(ctx context.Context, c *client.Client, path string, body any, etag string, out any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.BaseURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if etag != "" {
		req.Header.Set("If-Match", etag)
	}
	if c.APIKey != "" {
		req.Header.Set("X-API-Key", c.APIKey)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode >= 400 {
		return &client.APIError{Status: resp.StatusCode, Message: string(respBody)}
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func buildTenantProviderPayload(f emailProviderFlags) map[string]any {
	payload := map[string]any{
		"provider":  strings.ToLower(strings.TrimSpace(f.provider)),
		"fromEmail": strings.TrimSpace(f.fromEmail),
	}
	if strings.TrimSpace(f.replyTo) != "" {
		payload["replyTo"] = strings.TrimSpace(f.replyTo)
	}
	if f.timeoutMs > 0 {
		payload["timeoutMs"] = f.timeoutMs
	}
	if strings.TrimSpace(f.apiKey) != "" {
		payload["apiKey"] = strings.TrimSpace(f.apiKey)
	}
	if strings.TrimSpace(f.domain) != "" {
		payload["domain"] = strings.TrimSpace(f.domain)
	}
	if strings.TrimSpace(f.region) != "" {
		payload["region"] = strings.ToLower(strings.TrimSpace(f.region))
	}
	if payload["provider"] == "smtp" {
		payload["smtpHost"] = strings.TrimSpace(f.smtpHost)
		if f.smtpPort > 0 {
			payload["smtpPort"] = f.smtpPort
		}
		if strings.TrimSpace(f.smtpUser) != "" {
			payload["smtpUsername"] = strings.TrimSpace(f.smtpUser)
		}
		payload["smtpUseTLS"] = f.smtpTLS
		if strings.TrimSpace(f.smtpPass) != "" {
			payload["smtpPassword"] = f.smtpPass
		}
	}
	return payload
}

func buildLegacySMTPPayload(f emailProviderFlags) map[string]any {
	payload := map[string]any{
		"host":      strings.TrimSpace(f.smtpHost),
		"port":      f.smtpPort,
		"username":  strings.TrimSpace(f.smtpUser),
		"fromEmail": strings.TrimSpace(f.fromEmail),
		"useTLS":    f.smtpTLS,
	}
	if strings.TrimSpace(f.smtpPass) != "" {
		payload["password"] = f.smtpPass
	}
	return payload
}

func buildMailingSMTPOverridePayload(f emailProviderFlags) map[string]any {
	payload := map[string]any{
		"host":      strings.TrimSpace(f.smtpHost),
		"port":      f.smtpPort,
		"username":  strings.TrimSpace(f.smtpUser),
		"fromEmail": strings.TrimSpace(f.fromEmail),
		"useTLS":    f.smtpTLS,
	}
	if strings.TrimSpace(f.smtpPass) != "" {
		payload["password"] = f.smtpPass
	}
	return payload
}

func buildTestProviderPayload(f emailProviderFlags) map[string]any {
	payload := map[string]any{
		"kind":      strings.ToLower(strings.TrimSpace(f.provider)),
		"fromEmail": strings.TrimSpace(f.fromEmail),
	}
	if strings.TrimSpace(f.replyTo) != "" {
		payload["replyTo"] = strings.TrimSpace(f.replyTo)
	}
	if strings.TrimSpace(f.apiKey) != "" {
		payload["apiKey"] = strings.TrimSpace(f.apiKey)
	}
	if strings.TrimSpace(f.domain) != "" {
		payload["domain"] = strings.TrimSpace(f.domain)
	}
	if strings.TrimSpace(f.region) != "" {
		payload["region"] = strings.ToLower(strings.TrimSpace(f.region))
	}
	if f.timeoutMs > 0 {
		payload["timeoutMs"] = f.timeoutMs
	}
	return payload
}

func readTemplate(settings map[string]any, templateType string) (map[string]any, error) {
	mailing, _ := asMap(settings["mailing"])
	if mailing == nil {
		return nil, fmt.Errorf("mailing settings not configured")
	}
	templates, _ := asMap(mailing["templates"])
	if templates == nil {
		return nil, fmt.Errorf("mailing templates not configured")
	}
	tpl, _ := asMap(templates[templateType])
	if tpl == nil {
		return nil, fmt.Errorf("template %q not found", templateType)
	}
	return tpl, nil
}

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func toStr(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func toInt(v any, def int) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	default:
		return def
	}
}

func coalesce(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func orDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

type systemMailProviderResponse struct {
	Provider         string `json:"provider"`
	FromEmail        string `json:"fromEmail"`
	ReplyTo          string `json:"replyTo"`
	Domain           string `json:"domain"`
	Region           string `json:"region"`
	SMTPHost         string `json:"smtpHost"`
	SMTPPort         int    `json:"smtpPort"`
	SMTPUsername     string `json:"smtpUsername"`
	APIKeyConfigured bool   `json:"apiKeyConfigured"`
	UpdatedAt        string `json:"updatedAt"`
	UpdatedBy        string `json:"updatedBy"`
}

type systemMailGetResponse struct {
	EmailProvider   *systemMailProviderResponse `json:"emailProvider"`
	EffectiveSource string                      `json:"effectiveSource"`
}

type systemMailTestResponse struct {
	Success  bool   `json:"success"`
	Provider string `json:"provider"`
}

func printSystemMailStatus(raw json.RawMessage) error {
	var resp systemMailGetResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return err
	}

	switch strings.TrimSpace(resp.EffectiveSource) {
	case "control_plane":
		fmt.Println("Fuente:      Control Plane")
		ep := resp.EmailProvider
		if ep == nil || strings.TrimSpace(ep.Provider) == "" {
			fmt.Println("Provider:    (not configured)")
			return nil
		}
		fmt.Printf("Provider:    %s\n", ep.Provider)
		fmt.Printf("From:        %s\n", orDash(ep.FromEmail))
		fmt.Printf("Reply-To:    %s\n", orDash(ep.ReplyTo))
		if strings.EqualFold(ep.Provider, "smtp") {
			fmt.Printf("Host:        %s\n", orDash(ep.SMTPHost))
			if ep.SMTPPort > 0 {
				fmt.Printf("Port:        %d\n", ep.SMTPPort)
			}
			fmt.Printf("User:        %s\n", orDash(ep.SMTPUsername))
			if ep.APIKeyConfigured {
				fmt.Println("SMTP Pass:   [configured]")
			} else {
				fmt.Println("SMTP Pass:   [not set]")
			}
		} else {
			fmt.Printf("Domain:      %s\n", orDash(ep.Domain))
			fmt.Printf("Region:      %s\n", orDash(ep.Region))
			if ep.APIKeyConfigured {
				fmt.Println("API Key:     [configured]")
			} else {
				fmt.Println("API Key:     [not set]")
			}
		}
		if strings.TrimSpace(ep.UpdatedAt) != "" || strings.TrimSpace(ep.UpdatedBy) != "" {
			fmt.Printf("Updated:     %s", orDash(ep.UpdatedAt))
			if strings.TrimSpace(ep.UpdatedBy) != "" {
				fmt.Printf(" by %s", ep.UpdatedBy)
			}
			fmt.Println()
		}
	case "env":
		fmt.Println("Fuente:      Variables de entorno (solo lectura)")
		fmt.Println("Provider:    derived from env configuration")
	case "none":
		fmt.Println("Fuente:      Sin configuracion")
		fmt.Println("Efecto:      Tenants sin provider propio NO pueden enviar emails.")
	default:
		fmt.Printf("Fuente:      %s\n", orDash(resp.EffectiveSource))
	}

	return nil
}

func isValidProvider(p string) bool {
	switch p {
	case "smtp", "resend", "sendgrid", "mailgun":
		return true
	default:
		return false
	}
}
