//go:build integration

package emailv2

import (
	"context"
	"sync/atomic"
	"testing"
)

type matrixFakeSender struct {
	calls *int32
}

func (m *matrixFakeSender) Send(_ context.Context, _ string, _ string, _ string, _ string) error {
	atomic.AddInt32(m.calls, 1)
	return nil
}

func TestProviderMatrixIntegration(t *testing.T) {
	resetEmailMetricsForTests()

	providers := []ProviderKind{
		ProviderKindSMTP,
		ProviderKindResend,
		ProviderKindSendGrid,
		ProviderKindMailgun,
	}

	for _, p := range providers {
		provider := p
		var calls int32
		RegisterSenderBuilder(provider, func(EmailProviderConfig, string) (Sender, error) {
			return &matrixFakeSender{calls: &calls}, nil
		})

		cfg := integrationProviderConfig(provider)
		sender, err := BuildSenderFromConfig(cfg, "")
		if err != nil {
			t.Fatalf("provider %s: build sender: %v", provider, err)
		}
		if err := sender.Send(context.Background(), "ops@example.com", "test", "<p>ok</p>", "ok"); err != nil {
			t.Fatalf("provider %s: send failed: %v", provider, err)
		}
		if got := atomic.LoadInt32(&calls); got != 1 {
			t.Fatalf("provider %s: expected 1 send call, got %d", provider, got)
		}
	}

	totals, _, _, _ := snapshotEmailMetrics()
	for _, provider := range providers {
		key := emailSeries{Provider: string(provider), Status: "success"}
		if got := totals[key]; got != 1 {
			t.Fatalf("provider %s: expected success counter=1, got %d", provider, got)
		}
	}
}

func integrationProviderConfig(provider ProviderKind) EmailProviderConfig {
	cfg := EmailProviderConfig{
		Provider:  provider,
		FromEmail: "no-reply@example.com",
		ReplyTo:   "support@example.com",
		TimeoutMs: 1000,
		APIKey:    "test-key",
		Domain:    "mg.example.com",
		Region:    "us",
	}
	if provider == ProviderKindSMTP {
		cfg.SMTP = &SMTPConfig{
			Host:      "smtp.example.com",
			Port:      587,
			Username:  "smtp-user",
			Password:  "smtp-pass",
			FromEmail: "no-reply@example.com",
			UseTLS:    true,
		}
	}
	return cfg
}
