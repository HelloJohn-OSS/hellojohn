package mailgun

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	emailv2 "github.com/dropDatabas3/hellojohn/internal/email"
)

const (
	mailgunUSBaseURL = "https://api.mailgun.net"
	mailgunEUBaseURL = "https://api.eu.mailgun.net"
)

type mailgunSender struct {
	apiKey     string
	from       string
	replyTo    string
	domain     string
	baseURL    string
	httpClient *http.Client
}

// Build construye un sender Mailgun.
func Build(cfg emailv2.EmailProviderConfig, _ string) (emailv2.Sender, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, fmt.Errorf("%w: mailgun apiKey required", emailv2.ErrEmailConfig)
	}
	if strings.TrimSpace(cfg.FromEmail) == "" {
		return nil, fmt.Errorf("%w: mailgun fromEmail required", emailv2.ErrEmailConfig)
	}
	if strings.TrimSpace(cfg.Domain) == "" {
		return nil, fmt.Errorf("%w: mailgun domain required", emailv2.ErrEmailConfig)
	}

	region := strings.ToLower(strings.TrimSpace(cfg.Region))
	if region == "" {
		region = "us"
	}
	baseURL := mailgunUSBaseURL
	if region == "eu" {
		baseURL = mailgunEUBaseURL
	}
	if region != "us" && region != "eu" {
		return nil, fmt.Errorf("%w: mailgun region must be 'us' or 'eu'", emailv2.ErrEmailConfig)
	}

	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	return &mailgunSender{
		apiKey:  cfg.APIKey,
		from:    cfg.FromEmail,
		replyTo: cfg.ReplyTo,
		domain:  cfg.Domain,
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

func (s *mailgunSender) Send(ctx context.Context, to, subject, htmlBody, textBody string) error {
	form := url.Values{}
	form.Set("from", s.from)
	form.Set("to", to)
	form.Set("subject", subject)
	form.Set("html", htmlBody)
	form.Set("text", textBody)
	if strings.TrimSpace(s.replyTo) != "" {
		form.Set("h:Reply-To", s.replyTo)
	}

	endpoint := fmt.Sprintf("%s/v3/%s/messages", s.baseURL, url.PathEscape(s.domain))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return emailv2.WrapProviderError(emailv2.ProviderKindMailgun, emailv2.ErrEmailPermanent, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("api", s.apiKey)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return emailv2.WrapProviderError(emailv2.ProviderKindMailgun, emailv2.ErrEmailTemporary, err)
	}
	defer resp.Body.Close()

	return mapMailgunStatus(resp.StatusCode)
}

func mapMailgunStatus(code int) error {
	switch {
	case code >= 200 && code < 300:
		return nil
	case code == http.StatusUnauthorized:
		return emailv2.WrapProviderError(emailv2.ProviderKindMailgun, emailv2.ErrEmailAuth, fmt.Errorf("status %d", code))
	case code == http.StatusTooManyRequests:
		return emailv2.WrapProviderError(emailv2.ProviderKindMailgun, emailv2.ErrEmailRateLimited, fmt.Errorf("status %d", code))
	case code == http.StatusBadRequest || code == http.StatusForbidden || code == http.StatusUnprocessableEntity:
		return emailv2.WrapProviderError(emailv2.ProviderKindMailgun, emailv2.ErrEmailRejected, fmt.Errorf("status %d", code))
	case code >= 500:
		return emailv2.WrapProviderError(emailv2.ProviderKindMailgun, emailv2.ErrEmailTemporary, fmt.Errorf("status %d", code))
	default:
		return emailv2.WrapProviderError(emailv2.ProviderKindMailgun, emailv2.ErrEmailPermanent, fmt.Errorf("status %d", code))
	}
}

func init() {
	emailv2.RegisterSenderBuilder(emailv2.ProviderKindMailgun, Build)
}
