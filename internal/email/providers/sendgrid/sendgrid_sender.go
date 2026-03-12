package sendgrid

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

const sendGridBaseURL = "https://api.sendgrid.com"

type sendGridSender struct {
	apiKey     string
	from       string
	replyTo    string
	baseURL    string
	httpClient *http.Client
}

type sendGridEmailAddress struct {
	Email string `json:"email"`
}

type sendGridPersonalization struct {
	To []sendGridEmailAddress `json:"to"`
}

type sendGridContent struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type sendGridPayload struct {
	Personalizations []sendGridPersonalization `json:"personalizations"`
	From             sendGridEmailAddress      `json:"from"`
	Subject          string                    `json:"subject"`
	Content          []sendGridContent         `json:"content"`
	ReplyTo          *sendGridEmailAddress     `json:"reply_to,omitempty"`
}

// Build construye un sender SendGrid.
func Build(cfg emailv2.EmailProviderConfig, _ string) (emailv2.Sender, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, fmt.Errorf("%w: sendgrid apiKey required", emailv2.ErrEmailConfig)
	}
	if strings.TrimSpace(cfg.FromEmail) == "" {
		return nil, fmt.Errorf("%w: sendgrid fromEmail required", emailv2.ErrEmailConfig)
	}

	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	return &sendGridSender{
		apiKey:  cfg.APIKey,
		from:    cfg.FromEmail,
		replyTo: cfg.ReplyTo,
		baseURL: sendGridBaseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

func (s *sendGridSender) Send(ctx context.Context, to, subject, htmlBody, textBody string) error {
	content := make([]sendGridContent, 0, 2)
	if textBody != "" {
		content = append(content, sendGridContent{Type: "text/plain", Value: textBody})
	}
	if htmlBody != "" {
		content = append(content, sendGridContent{Type: "text/html", Value: htmlBody})
	}
	if len(content) == 0 {
		content = append(content, sendGridContent{Type: "text/plain", Value: subject})
	}

	payload := sendGridPayload{
		Personalizations: []sendGridPersonalization{
			{To: []sendGridEmailAddress{{Email: to}}},
		},
		From:    sendGridEmailAddress{Email: s.from},
		Subject: subject,
		Content: content,
	}
	if s.replyTo != "" {
		payload.ReplyTo = &sendGridEmailAddress{Email: s.replyTo}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return emailv2.WrapProviderError(emailv2.ProviderKindSendGrid, emailv2.ErrEmailPermanent, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/v3/mail/send", bytes.NewReader(body))
	if err != nil {
		return emailv2.WrapProviderError(emailv2.ProviderKindSendGrid, emailv2.ErrEmailPermanent, err)
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return emailv2.WrapProviderError(emailv2.ProviderKindSendGrid, emailv2.ErrEmailTemporary, err)
	}
	defer resp.Body.Close()

	return mapSendGridStatus(resp.StatusCode)
}

func mapSendGridStatus(code int) error {
	switch {
	case code >= 200 && code < 300:
		return nil
	case code == http.StatusUnauthorized:
		return emailv2.WrapProviderError(emailv2.ProviderKindSendGrid, emailv2.ErrEmailAuth, fmt.Errorf("status %d", code))
	case code == http.StatusTooManyRequests:
		return emailv2.WrapProviderError(emailv2.ProviderKindSendGrid, emailv2.ErrEmailRateLimited, fmt.Errorf("status %d", code))
	case code == http.StatusBadRequest || code == http.StatusForbidden || code == http.StatusUnprocessableEntity:
		return emailv2.WrapProviderError(emailv2.ProviderKindSendGrid, emailv2.ErrEmailRejected, fmt.Errorf("status %d", code))
	case code >= 500:
		return emailv2.WrapProviderError(emailv2.ProviderKindSendGrid, emailv2.ErrEmailTemporary, fmt.Errorf("status %d", code))
	default:
		return emailv2.WrapProviderError(emailv2.ProviderKindSendGrid, emailv2.ErrEmailPermanent, fmt.Errorf("status %d", code))
	}
}

func init() {
	emailv2.RegisterSenderBuilder(emailv2.ProviderKindSendGrid, Build)
}
