package oauth

import (
	"testing"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

func TestIsGrantTypeAllowedWithProfiles(t *testing.T) {
	t.Parallel()

	client := &repository.Client{
		ClientID:       "app",
		AuthProfile:    "m2m",
		GrantTypes:     []string{"client_credentials"},
		AccessTokenTTL: 3600,
	}

	if isGrantTypeAllowed(client, "authorization_code", true) {
		t.Fatalf("m2m profile should reject authorization_code when profiles are enabled")
	}
	if !isGrantTypeAllowed(client, "client_credentials", true) {
		t.Fatalf("m2m profile should allow client_credentials")
	}
	if !isGrantTypeAllowed(client, "client_credentials", false) {
		t.Fatalf("grant list should still allow client_credentials when profiles are disabled")
	}
}

func TestResolveEffectiveTTLSeconds(t *testing.T) {
	t.Parallel()

	if got := resolveEffectiveTTLSeconds(3600, 7200, 30*time.Second); got != 3600 {
		t.Fatalf("client ttl should win, got=%d", got)
	}
	if got := resolveEffectiveTTLSeconds(0, 7200, 30*time.Second); got != 7200 {
		t.Fatalf("tenant ttl should win when client is absent, got=%d", got)
	}
	if got := resolveEffectiveTTLSeconds(0, 0, 30*time.Second); got != 30 {
		t.Fatalf("global ttl should be used as fallback, got=%d", got)
	}
}

func TestIsGrantAllowedForAuthorize(t *testing.T) {
	t.Parallel()

	client := &repository.Client{
		ClientID:    "api",
		AuthProfile: "m2m",
		GrantTypes:  []string{"client_credentials"},
	}
	if isGrantAllowedForAuthorize(client, true) {
		t.Fatalf("authorize must be rejected for m2m profile")
	}
	if isGrantAllowedForAuthorize(client, false) {
		t.Fatalf("authorize must still be rejected by explicit grant list")
	}

	web := &repository.Client{
		ClientID:    "web",
		AuthProfile: "web_ssr",
		GrantTypes:  []string{"authorization_code", "refresh_token"},
	}
	if !isGrantAllowedForAuthorize(web, true) {
		t.Fatalf("authorize must be allowed for web_ssr with authorization_code grant")
	}
}

func TestSubtleEq(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{name: "equal", a: "secret-value", b: "secret-value", want: true},
		{name: "different-same-length", a: "secret-value", b: "secret-valuE", want: false},
		{name: "different-length", a: "secret-value", b: "secret-value-2", want: false},
		{name: "both-empty", a: "", b: "", want: true},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := subtleEq(tc.a, tc.b); got != tc.want {
				t.Fatalf("subtleEq(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
