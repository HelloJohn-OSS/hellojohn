package audit

import (
	"context"
	"encoding/json"
	"log"
)

// Writer is the interface for audit event consumers.
// Implementations must be safe for concurrent use.
type Writer interface {
	Write(ctx context.Context, events []AuditEvent) error
}

// metadataAllowlist defines the keys that are safe to log in StdoutWriter.
// Any key NOT in this list is redacted to prevent accidental PII/secret leakage.
var metadataAllowlist = map[string]bool{
	"method":      true,
	"admin_type":  true,
	"provider":    true,
	"grant_type":  true,
	"scope":       true,
	"client_id":   true,
	"role":        true,
	"reason":      true,
	"otp_channel": true,
	"tenant_slug": true,
}

// StdoutWriter writes audit events to stdout as JSON lines.
// Metadata is filtered through an allowlist to prevent accidental PII exposure.
type StdoutWriter struct{}

func (w *StdoutWriter) Write(_ context.Context, events []AuditEvent) error {
	for _, e := range events {
		safe := e
		safe.Metadata = redactMetadata(e.Metadata)
		b, err := json.Marshal(safe)
		if err != nil {
			log.Printf("ERR: audit marshal: %v", err)
			continue
		}
		log.Printf("AUDIT: %s", b)
	}
	return nil
}

// redactMetadata returns a copy of the metadata map with only allowlisted keys.
// Non-allowlisted keys are replaced with "[REDACTED]".
func redactMetadata(m map[string]any) map[string]any {
	if len(m) == 0 {
		return m
	}
	safe := make(map[string]any, len(m))
	for k, v := range m {
		if metadataAllowlist[k] {
			safe[k] = v
		} else {
			safe[k] = "[REDACTED]"
		}
	}
	return safe
}
