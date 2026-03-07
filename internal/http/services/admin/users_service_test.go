package admin

import "testing"

func TestGenerateSecureToken_ReadError(t *testing.T) {
	orig := secureTokenReader
	secureTokenReader = errReader{}
	defer func() { secureTokenReader = orig }()

	token, err := generateSecureToken()
	if err == nil {
		t.Fatalf("expected error, got token=%q", token)
	}
}
