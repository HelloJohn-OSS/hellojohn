package sms

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type vonageProvider struct {
	apiKey    string
	apiSecret string
	from      string
	client    *http.Client
}

type vonageResponse struct {
	Messages []struct {
		Status string `json:"status"`
	} `json:"messages"`
}

func newVonageProvider(cfg Config) (SMSProvider, error) {
	if strings.TrimSpace(cfg.VonageAPIKey) == "" ||
		strings.TrimSpace(cfg.VonageAPISecret) == "" ||
		strings.TrimSpace(cfg.VonageFrom) == "" {
		return nil, ErrProviderNotConfigured
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &vonageProvider{
		apiKey:    strings.TrimSpace(cfg.VonageAPIKey),
		apiSecret: strings.TrimSpace(cfg.VonageAPISecret),
		from:      strings.TrimSpace(cfg.VonageFrom),
		client:    &http.Client{Timeout: timeout},
	}, nil
}

func (p *vonageProvider) Send(ctx context.Context, to string, body string) error {
	values := url.Values{}
	values.Set("api_key", p.apiKey)
	values.Set("api_secret", p.apiSecret)
	values.Set("to", strings.TrimSpace(to))
	values.Set("from", p.from)
	values.Set("text", body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://rest.nexmo.com/sms/json", strings.NewReader(values.Encode()))
	if err != nil {
		return fmt.Errorf("%w: request build", ErrSendFailed)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: request failed", ErrSendFailed)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%w: vonage http %d", ErrSendFailed, resp.StatusCode)
	}

	var payload vonageResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return fmt.Errorf("%w: invalid provider response", ErrSendFailed)
	}
	if len(payload.Messages) == 0 || payload.Messages[0].Status != "0" {
		return fmt.Errorf("%w: provider rejected message", ErrSendFailed)
	}
	return nil
}
