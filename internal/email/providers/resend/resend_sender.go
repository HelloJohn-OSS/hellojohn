package resend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	emailv2 "github.com/dropDatabas3/hellojohn/internal/email"
)

const resendBaseURL = "https://api.resend.com"

type resendSender struct {
	apiKey     string
	from       string
	replyTo    string
	baseURL    string
	httpClient *http.Client
}

type resendEmailPayload struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html,omitempty"`
	Text    string   `json:"text,omitempty"`
	ReplyTo string   `json:"reply_to,omitempty"`
}

// Build construye un sender Resend.
func Build(cfg emailv2.EmailProviderConfig, _ string) (emailv2.Sender, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, fmt.Errorf("%w: resend apiKey required", emailv2.ErrEmailConfig)
	}
	if strings.TrimSpace(cfg.FromEmail) == "" {
		return nil, fmt.Errorf("%w: resend fromEmail required", emailv2.ErrEmailConfig)
	}

	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	return &resendSender{
		apiKey:  cfg.APIKey,
		from:    cfg.FromEmail,
		replyTo: cfg.ReplyTo,
		baseURL: resendBaseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

func (s *resendSender) Send(ctx context.Context, to, subject, htmlBody, textBody string) error {
	payload := resendEmailPayload{
		From:    s.from,
		To:      []string{to},
		Subject: subject,
		HTML:    htmlBody,
		Text:    textBody,
		ReplyTo: s.replyTo,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return emailv2.WrapProviderError(emailv2.ProviderKindResend, emailv2.ErrEmailPermanent, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/emails", bytes.NewReader(body))
	if err != nil {
		return emailv2.WrapProviderError(emailv2.ProviderKindResend, emailv2.ErrEmailPermanent, err)
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return emailv2.WrapProviderError(emailv2.ProviderKindResend, emailv2.ErrEmailTemporary, err)
	}
	defer resp.Body.Close()

	return mapResendStatus(resp.StatusCode)
}

func mapResendStatus(code int) error {
	switch {
	case code >= 200 && code < 300:
		return nil
	case code == http.StatusUnauthorized:
		return emailv2.WrapProviderError(emailv2.ProviderKindResend, emailv2.ErrEmailAuth, fmt.Errorf("status %d", code))
	case code == http.StatusTooManyRequests:
		return emailv2.WrapProviderError(emailv2.ProviderKindResend, emailv2.ErrEmailRateLimited, fmt.Errorf("status %d", code))
	case code == http.StatusBadRequest || code == http.StatusForbidden || code == http.StatusUnprocessableEntity:
		return emailv2.WrapProviderError(emailv2.ProviderKindResend, emailv2.ErrEmailRejected, fmt.Errorf("status %d", code))
	case code >= 500:
		return emailv2.WrapProviderError(emailv2.ProviderKindResend, emailv2.ErrEmailTemporary, fmt.Errorf("status %d", code))
	default:
		return emailv2.WrapProviderError(emailv2.ProviderKindResend, emailv2.ErrEmailPermanent, fmt.Errorf("status %d", code))
	}
}

func init() {
	emailv2.RegisterSenderBuilder(emailv2.ProviderKindResend, Build)
}
