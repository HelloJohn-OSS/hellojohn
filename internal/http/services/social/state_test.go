package social

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

type stateIssuerStub struct {
	iss  string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func (s *stateIssuerStub) SignRaw(claims jwtv5.MapClaims) (string, string, error) {
	tk := jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, claims)
	tk.Header["kid"] = "kid-1"
	signed, err := tk.SignedString(s.priv)
	return signed, "kid-1", err
}

func (s *stateIssuerStub) Keyfunc() jwtv5.Keyfunc {
	return func(*jwtv5.Token) (any, error) {
		return s.pub, nil
	}
}

func (s *stateIssuerStub) Iss() string {
	return s.iss
}

type stateStructIssuerStub struct {
	inner *stateIssuerStub
}

func (s stateStructIssuerStub) Keyfunc() jwtv5.Keyfunc {
	return s.inner.Keyfunc()
}

func (s stateStructIssuerStub) SignRaw(claims jwtv5.MapClaims) (string, string, error) {
	return s.inner.SignRaw(claims)
}

func (s stateStructIssuerStub) GetIss() string {
	return s.inner.Iss()
}

func newStateSigner(t *testing.T) *IssuerAdapter {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	return &IssuerAdapter{
		Issuer: &stateIssuerStub{
			iss:  "https://auth.example.com",
			priv: priv,
			pub:  pub,
		},
		StateTTL: 5 * time.Minute,
	}
}

func TestIssuerAdapter_SignAndParseState(t *testing.T) {
	adapter := newStateSigner(t)

	token, err := adapter.SignState(StateClaims{
		Provider:    "google",
		TenantSlug:  "tenant-a",
		ClientID:    "client-a",
		RedirectURI: "https://app.example.com/callback",
		Nonce:       "nonce-a",
	})
	if err != nil {
		t.Fatalf("sign state: %v", err)
	}

	claims, err := adapter.ParseState(token)
	if err != nil {
		t.Fatalf("parse state: %v", err)
	}
	if claims.Provider != "google" || claims.TenantSlug != "tenant-a" || claims.ClientID != "client-a" {
		t.Fatalf("unexpected claims: %#v", claims)
	}
}

func TestIssuerAdapter_ParseStateValidationErrors(t *testing.T) {
	adapter := newStateSigner(t)
	issuer := adapter.Issuer.(*stateIssuerStub)

	mustSign := func(claims jwtv5.MapClaims) string {
		tk := jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, claims)
		token, err := tk.SignedString(issuer.priv)
		if err != nil {
			t.Fatalf("sign token: %v", err)
		}
		return token
	}

	_, err := adapter.ParseState("bad-token")
	if err != ErrStateInvalid {
		t.Fatalf("expected ErrStateInvalid, got %v", err)
	}

	badIssuer := mustSign(jwtv5.MapClaims{
		"iss": "https://wrong.example.com",
		"aud": StateAudience,
		"exp": time.Now().Add(1 * time.Minute).Unix(),
	})
	_, err = adapter.ParseState(badIssuer)
	if err != ErrStateIssuer {
		t.Fatalf("expected ErrStateIssuer, got %v", err)
	}

	badAudience := mustSign(jwtv5.MapClaims{
		"iss": adapter.Issuer.Iss(),
		"aud": "other-audience",
		"exp": time.Now().Add(1 * time.Minute).Unix(),
	})
	_, err = adapter.ParseState(badAudience)
	if err != ErrStateAudience {
		t.Fatalf("expected ErrStateAudience, got %v", err)
	}

	expired := mustSign(jwtv5.MapClaims{
		"iss": adapter.Issuer.Iss(),
		"aud": StateAudience,
		"exp": time.Now().Add(-2 * time.Minute).Unix(),
	})
	_, err = adapter.ParseState(expired)
	if err != ErrStateInvalid && err != ErrStateExpired {
		t.Fatalf("expected ErrStateInvalid or ErrStateExpired, got %v", err)
	}

	legacyAudience := mustSign(jwtv5.MapClaims{
		"iss":         adapter.Issuer.Iss(),
		"aud":         StateAudienceLegacy,
		"exp":         time.Now().Add(1 * time.Minute).Unix(),
		"provider":    "google",
		"tenant_slug": "tenant-a",
		"cid":         "client-a",
		"nonce":       "nonce-a",
	})
	if _, err := adapter.ParseState(legacyAudience); err != nil {
		t.Fatalf("expected legacy audience to pass, got %v", err)
	}
}

func TestNewIssuerAdapter(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	base := &stateIssuerStub{
		iss:  "https://auth.example.com",
		priv: priv,
		pub:  pub,
	}

	adapter := NewIssuerAdapter(stateStructIssuerStub{inner: base}, time.Minute)
	token, err := adapter.SignState(StateClaims{
		Provider:   "google",
		TenantSlug: "tenant-a",
		ClientID:   "client-a",
		Nonce:      "nonce-a",
	})
	if err != nil {
		t.Fatalf("sign via wrapped adapter: %v", err)
	}
	if _, err := adapter.ParseState(token); err != nil {
		t.Fatalf("parse via wrapped adapter: %v", err)
	}
}

func TestGetString(t *testing.T) {
	claims := map[string]any{"k": "v", "n": 123}
	if got := getString(claims, "k"); got != "v" {
		t.Fatalf("expected v, got %q", got)
	}
	if got := getString(claims, "n"); got != "" {
		t.Fatalf("expected empty for non-string, got %q", got)
	}
}
