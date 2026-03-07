package security

import (
	"testing"
)

func TestGenerateOTP_Length6(t *testing.T) {
	otp, err := GenerateOTP(6)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(otp) != 6 {
		t.Fatalf("expected length 6, got %d", len(otp))
	}
	// All characters must be digits
	for _, c := range otp {
		if c < '0' || c > '9' {
			t.Fatalf("expected digit, got %c", c)
		}
	}
}

func TestGenerateOTP_ZeroLength(t *testing.T) {
	otp, err := GenerateOTP(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if otp != "" {
		t.Fatalf("expected empty string, got %q", otp)
	}
}

func TestGenerateOTP_NegativeLength(t *testing.T) {
	otp, err := GenerateOTP(-1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if otp != "" {
		t.Fatalf("expected empty string, got %q", otp)
	}
}

func TestGenerateOTP_Uniqueness(t *testing.T) {
	seen := make(map[string]struct{})
	duplicates := 0
	for i := 0; i < 1000; i++ {
		otp, err := GenerateOTP(6)
		if err != nil {
			t.Fatalf("unexpected error at iteration %d: %v", i, err)
		}
		if _, ok := seen[otp]; ok {
			duplicates++
		}
		seen[otp] = struct{}{}
	}
	// En 1000 intentos de 6 dígitos (10^6 = 1M posibles), algunos duplicados
	// son posibles pero no deberían exceder un 2% con buena aleatoriedad
	if duplicates > 20 {
		t.Fatalf("too many duplicates: %d out of 1000", duplicates)
	}
}

func TestGenerateOpaqueToken(t *testing.T) {
	token, err := GenerateOpaqueToken(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(token) != 32 {
		t.Fatalf("expected length 32, got %d", len(token))
	}
	// All characters must be URL-safe
	for _, c := range token {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			t.Fatalf("non-URL-safe character: %c", c)
		}
	}
}
