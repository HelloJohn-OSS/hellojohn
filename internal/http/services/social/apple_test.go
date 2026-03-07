package social

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

func TestAppleVerifyIDToken_ValidSignatureAndClaims(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	kid := "kid-valid"
	jwksServer := newAppleJWKSServer(t, kid, &privateKey.PublicKey)
	defer jwksServer.Close()

	clientID := "com.example.app"
	now := time.Now()
	idToken := mustSignAppleJWT(t, privateKey, kid, map[string]any{
		"iss":            appleIssuer,
		"aud":            clientID,
		"sub":            "apple-user-123",
		"email":          "john@example.com",
		"email_verified": "true",
		"nonce":          "nonce-123",
		"exp":            now.Add(10 * time.Minute).Unix(),
		"iat":            now.Unix(),
	})

	adapter := &appleAdapter{
		clientID:   clientID,
		httpClient: jwksServer.Client(),
		issuer:     appleIssuer,
		jwksURL:    jwksServer.URL,
		jwksTTL:    time.Hour,
	}

	claims, err := adapter.VerifyIDToken(context.Background(), idToken, "nonce-123")
	if err != nil {
		t.Fatalf("VerifyIDToken returned error: %v", err)
	}
	if claims.Sub != "apple-user-123" {
		t.Fatalf("expected sub apple-user-123, got %q", claims.Sub)
	}
	if claims.Email != "john@example.com" {
		t.Fatalf("expected email john@example.com, got %q", claims.Email)
	}
	if !claims.EmailVerified {
		t.Fatalf("expected EmailVerified true")
	}
}

func TestAppleVerifyIDToken_InvalidSignatureFails(t *testing.T) {
	validKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate valid rsa key: %v", err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate invalid rsa key: %v", err)
	}

	kid := "kid-signature"
	jwksServer := newAppleJWKSServer(t, kid, &validKey.PublicKey)
	defer jwksServer.Close()

	idToken := mustSignAppleJWT(t, otherKey, kid, map[string]any{
		"iss":            appleIssuer,
		"aud":            "com.example.app",
		"sub":            "apple-user-123",
		"email":          "john@example.com",
		"email_verified": true,
		"nonce":          "nonce-123",
		"exp":            time.Now().Add(10 * time.Minute).Unix(),
		"iat":            time.Now().Unix(),
	})

	adapter := &appleAdapter{
		clientID:   "com.example.app",
		httpClient: jwksServer.Client(),
		issuer:     appleIssuer,
		jwksURL:    jwksServer.URL,
		jwksTTL:    time.Hour,
	}

	if _, err := adapter.VerifyIDToken(context.Background(), idToken, "nonce-123"); err == nil {
		t.Fatalf("expected signature verification to fail")
	}
}

func TestAppleVerifyIDToken_RejectsBadIssuerAudienceNonce(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	kid := "kid-claims"
	jwksServer := newAppleJWKSServer(t, kid, &privateKey.PublicKey)
	defer jwksServer.Close()

	now := time.Now()
	testCases := []struct {
		name          string
		claims        map[string]any
		expectedNonce string
	}{
		{
			name: "bad issuer",
			claims: map[string]any{
				"iss":            "https://evil.example.com",
				"aud":            "com.example.app",
				"sub":            "s1",
				"email":          "a@example.com",
				"email_verified": true,
				"nonce":          "nonce-1",
				"exp":            now.Add(10 * time.Minute).Unix(),
			},
			expectedNonce: "nonce-1",
		},
		{
			name: "bad audience",
			claims: map[string]any{
				"iss":            appleIssuer,
				"aud":            "com.wrong.app",
				"sub":            "s1",
				"email":          "a@example.com",
				"email_verified": true,
				"nonce":          "nonce-1",
				"exp":            now.Add(10 * time.Minute).Unix(),
			},
			expectedNonce: "nonce-1",
		},
		{
			name: "bad nonce",
			claims: map[string]any{
				"iss":            appleIssuer,
				"aud":            "com.example.app",
				"sub":            "s1",
				"email":          "a@example.com",
				"email_verified": true,
				"nonce":          "nonce-other",
				"exp":            now.Add(10 * time.Minute).Unix(),
			},
			expectedNonce: "nonce-1",
		},
		{
			name: "expired token",
			claims: map[string]any{
				"iss":            appleIssuer,
				"aud":            "com.example.app",
				"sub":            "s1",
				"email":          "a@example.com",
				"email_verified": true,
				"nonce":          "nonce-1",
				"exp":            now.Add(-10 * time.Minute).Unix(),
			},
			expectedNonce: "nonce-1",
		},
	}

	adapter := &appleAdapter{
		clientID:   "com.example.app",
		httpClient: jwksServer.Client(),
		issuer:     appleIssuer,
		jwksURL:    jwksServer.URL,
		jwksTTL:    time.Hour,
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			idToken := mustSignAppleJWT(t, privateKey, kid, tc.claims)
			if _, err := adapter.VerifyIDToken(context.Background(), idToken, tc.expectedNonce); err == nil {
				t.Fatalf("expected verification to fail for %s", tc.name)
			}
		})
	}
}

func newAppleJWKSServer(t *testing.T, kid string, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()

	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"kid": kid,
				"alg": "RS256",
				"use": "sig",
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(bigEndianInt(pub.E)),
			},
		},
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks)
	}))
}

func mustSignAppleJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()

	token := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, jwtv5.MapClaims(claims))
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func bigEndianInt(v int) []byte {
	if v == 0 {
		return []byte{0}
	}
	out := make([]byte, 0, 4)
	for v > 0 {
		out = append([]byte{byte(v & 0xff)}, out...)
		v >>= 8
	}
	return out
}
