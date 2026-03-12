package emailv2

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeSender struct {
	errs  []error
	calls int
}

func (f *fakeSender) Send(_ context.Context, _ string, _ string, _ string, _ string) error {
	f.calls++
	if f.calls <= len(f.errs) {
		return f.errs[f.calls-1]
	}
	return nil
}

func TestRetryOnTemporaryError(t *testing.T) {
	resetEmailMetricsForTests()

	base := &fakeSender{
		errs: []error{ErrEmailTemporary, ErrEmailTemporary, nil},
	}
	sender := &resilientSender{
		provider:    ProviderKindResend,
		inner:       base,
		maxAttempts: 3,
		baseBackoff: time.Millisecond,
	}

	if err := sender.Send(context.Background(), "a@example.com", "subject", "<p>ok</p>", "ok"); err != nil {
		t.Fatalf("expected success after retries, got err: %v", err)
	}
	if base.calls != 3 {
		t.Fatalf("expected 3 attempts, got %d", base.calls)
	}

	totals, _, _, _ := snapshotEmailMetrics()
	if got := totals[emailSeries{Provider: "resend", Status: "success"}]; got != 1 {
		t.Fatalf("expected resend/success=1, got %d", got)
	}
}

func TestRetryStopsOnPermanentError(t *testing.T) {
	resetEmailMetricsForTests()

	base := &fakeSender{
		errs: []error{ErrEmailPermanent},
	}
	sender := &resilientSender{
		provider:    ProviderKindSendGrid,
		inner:       base,
		maxAttempts: 3,
		baseBackoff: time.Millisecond,
	}

	err := sender.Send(context.Background(), "a@example.com", "subject", "<p>ok</p>", "ok")
	if !errors.Is(err, ErrEmailPermanent) {
		t.Fatalf("expected ErrEmailPermanent, got %v", err)
	}
	if base.calls != 1 {
		t.Fatalf("expected 1 attempt for permanent error, got %d", base.calls)
	}

	totals, _, _, _ := snapshotEmailMetrics()
	if got := totals[emailSeries{Provider: "sendgrid", Status: "permanent"}]; got != 1 {
		t.Fatalf("expected sendgrid/permanent=1, got %d", got)
	}
}

func TestWritePrometheusEmailMetrics(t *testing.T) {
	resetEmailMetricsForTests()
	recordEmailSendMetric(ProviderKindSMTP, "success", 120*time.Millisecond)
	recordEmailSendMetric(ProviderKindSMTP, "success", 220*time.Millisecond)

	var b strings.Builder
	WritePrometheusEmailMetrics(&b)
	out := b.String()

	if !strings.Contains(out, "email_send_total{provider=\"smtp\",status=\"success\"} 2") {
		t.Fatalf("expected email_send_total series in output, got:\n%s", out)
	}
	if !strings.Contains(out, "email_send_duration_seconds_count{provider=\"smtp\",status=\"success\"} 2") {
		t.Fatalf("expected email_send_duration_seconds_count in output, got:\n%s", out)
	}
}
