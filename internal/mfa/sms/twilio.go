package sms

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type twilioProvider struct {
	accountSID string
	authToken  string
	from       string
	client     *http.Client
}

func newTwilioProvider(cfg Config) (SMSProvider, error) {
	if strings.TrimSpace(cfg.TwilioAccountSID) == "" ||
		strings.TrimSpace(cfg.TwilioAuthToken) == "" ||
		strings.TrimSpace(cfg.TwilioFrom) == "" {
		return nil, ErrProviderNotConfigured
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &twilioProvider{
		accountSID: strings.TrimSpace(cfg.TwilioAccountSID),
		authToken:  strings.TrimSpace(cfg.TwilioAuthToken),
		from:       strings.TrimSpace(cfg.TwilioFrom),
		client:     &http.Client{Timeout: timeout},
	}, nil
}

func (p *twilioProvider) Send(ctx context.Context, to string, body string) error {
	values := url.Values{}
	values.Set("To", strings.TrimSpace(to))
	values.Set("From", p.from)
	values.Set("Body", body)

	endpoint := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", url.PathEscape(p.accountSID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return fmt.Errorf("%w: request build", ErrSendFailed)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.accountSID, p.authToken)

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: request failed", ErrSendFailed)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: twilio http %d", ErrSendFailed, resp.StatusCode)
	}
	return nil
}
