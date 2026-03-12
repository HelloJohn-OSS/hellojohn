package emailv2

import (
	"context"
	"errors"
	"time"
)

const (
	defaultEmailMaxAttempts = 3
	defaultEmailBaseBackoff = 200 * time.Millisecond
)

// resilientSender wraps provider senders with retry + metrics instrumentation.
// Retry policy:
//   - max 3 attempts total
//   - retries only on ErrEmailTemporary
//   - exponential backoff (200ms, 400ms)
type resilientSender struct {
	provider    ProviderKind
	inner       Sender
	maxAttempts int
	baseBackoff time.Duration
}

func wrapResilientSender(provider ProviderKind, inner Sender) Sender {
	if inner == nil {
		return nil
	}
	return &resilientSender{
		provider:    provider,
		inner:       inner,
		maxAttempts: defaultEmailMaxAttempts,
		baseBackoff: defaultEmailBaseBackoff,
	}
}

func (s *resilientSender) Send(ctx context.Context, to, subject, htmlBody, textBody string) error {
	start := time.Now()
	err := s.sendWithRetry(ctx, to, subject, htmlBody, textBody)
	recordEmailSendMetric(s.provider, classifyEmailSendStatus(err), time.Since(start))
	return err
}

func (s *resilientSender) sendWithRetry(ctx context.Context, to, subject, htmlBody, textBody string) error {
	attempts := s.maxAttempts
	if attempts <= 0 {
		attempts = 1
	}
	base := s.baseBackoff
	if base <= 0 {
		base = defaultEmailBaseBackoff
	}

	var err error
	for attempt := 1; attempt <= attempts; attempt++ {
		err = s.inner.Send(ctx, to, subject, htmlBody, textBody)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrEmailTemporary) || attempt == attempts {
			return err
		}

		backoff := base * time.Duration(1<<(attempt-1))
		if waitErr := waitWithContext(ctx, backoff); waitErr != nil {
			return waitErr
		}
	}
	return err
}

func waitWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func classifyEmailSendStatus(err error) string {
	switch {
	case err == nil:
		return "success"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return "canceled"
	case errors.Is(err, ErrEmailTemporary):
		return "temporary"
	case errors.Is(err, ErrEmailRateLimited):
		return "rate_limited"
	case errors.Is(err, ErrEmailRejected):
		return "rejected"
	case errors.Is(err, ErrEmailAuth):
		return "auth"
	case errors.Is(err, ErrEmailConfig):
		return "config"
	case errors.Is(err, ErrEmailPermanent):
		return "permanent"
	default:
		return "error"
	}
}
