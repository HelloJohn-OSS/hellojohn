package admin

import (
	"testing"
)

// Test that new methods compile
func TestRevokeSecretCompiles(t *testing.T) {
	// Test generateClientSecret
	secret, err := generateClientSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) == 0 {
		t.Fatal("expected non-empty secret")
	}
	t.Logf("Generated secret: %s (length: %d)", secret, len(secret))
}
