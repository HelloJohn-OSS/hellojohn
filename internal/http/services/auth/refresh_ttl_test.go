package auth

import (
	"testing"
	"time"
)

func TestEffectiveTTLSeconds(t *testing.T) {
	t.Parallel()

	if got := effectiveTTLSeconds(3600, 7200, 30*time.Second); got != 3600 {
		t.Fatalf("client ttl should win, got=%d", got)
	}
	if got := effectiveTTLSeconds(0, 7200, 30*time.Second); got != 7200 {
		t.Fatalf("tenant ttl should win, got=%d", got)
	}
	if got := effectiveTTLSeconds(0, 0, 30*time.Second); got != 30 {
		t.Fatalf("global ttl should be used, got=%d", got)
	}
}
