package resolver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/security/secretbox"
)

func init() {
	// Preparar Entorno AES Mockeado 32 bytes para los Tests Unitarios
	secretbox.UnsafeResetSecretBoxForTests()
	os.Setenv("SECRETBOX_MASTER_KEY", "bXlzdXBlcnNlY3JldGtleXRoYXRpczMyYnl0ZXNsb25n") // mock base64
}

func mockSecretBox(plain string) string {
	enc, _ := secretbox.Encrypt(plain)
	return enc
}

func TestWebhookResolver_SSRF_Protection(t *testing.T) {
	encSecret := mockSecretBox("my-dummy-tenant-secret")

	tests := []struct {
		url     string
		wantErr bool
	}{
		{"http://localhost:8080/api/claims", true}, // Bloquea Loopback
		{"http://127.0.0.1/auth", true},            // Bloquea IPv4 Loopback
		{"http://10.0.5.1/internal-claims", true},  // Bloquea VPC Subnets
		{"http://169.254.169.254/meta", true},      // AWS Metadata Attack
		{"https://api.github.com/webhook", false},  // External Permitted (Real DNS resolution required for LookupIP to avoid panic reject)
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("SSRF test: %s", tc.url), func(t *testing.T) {
			resolver, err := NewWebhookResolver(tc.url, encSecret, 500*time.Millisecond, nil)

			if tc.wantErr {
				if err == nil {
					t.Errorf("expected SSRF mitigation error for %s, but got none", tc.url)
				}
				if resolver != nil {
					t.Errorf("resolver expected to be nil on SSRF blocks")
				}
			} else {
				if err != nil {
					if strings.Contains(err.Error(), "SSRF") {
						t.Errorf("unexpected SSRF flag for public URI %s: %v", tc.url, err)
					}
				}
			}
		})
	}
}

func TestWebhookResolver_Success_And_DataFormat(t *testing.T) {
	encSecret := mockSecretBox("tenant_wh_secret")

	// 1. Instanciamos mock Server.
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify required headers by Jwtx HMAC integration.
		if r.Header.Get("X-HelloJohn-Signature") == "" {
			t.Errorf("Missing HMAC Signature header")
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		// Testeando el Mapeo Inteligente (diccionario en bruto).
		fmt.Fprintln(w, `{"value": ["premium_user", "forum_mod"]}`)
	}))
	defer mockServer.Close()

	// Como httptest levanta en 127.0.0.1 (Loopback), nuestra librería Anti-SSRF va a gritar y
	// frenar el instanciador devolviendo `err("Invalid Webhook URL")`.
	// Para testear el flujo "Resolve()", falseamos el struct constructor y pisamos URL.
	resolver := &WebhookResolver{
		URL:          mockServer.URL,
		SecretEnc:    encSecret,
		parsedSecret: "tenant_wh_secret",
		Timeout:      1 * time.Second,
	}

	ctx := context.Background()
	input := ResolverInput{UserID: "uuid-123"}

	t.Run("successful claim extraction map value", func(t *testing.T) {
		val, err := resolver.Resolve(ctx, input)
		if err != nil {
			t.Fatalf("unexpected execution error: %v", err)
		}

		// Because we mocked `{"value": [...] }` the resolver should have flattened the array automatically.
		arr, ok := val.([]any)
		if !ok || len(arr) != 2 {
			t.Errorf("expected mapped unmarshalled primitive array, got: %v", val)
		}
	})
}

func TestWebhookResolver_Timeboxing_DoS_Timeout(t *testing.T) {
	// Configuramos API remota LENTA
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1 * time.Second) // Force delay de 1 segundo en el cloud remoto
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"value": "tarde"}`)
	}))
	defer mockServer.Close()

	resolver := &WebhookResolver{
		URL:          mockServer.URL,
		parsedSecret: "dummy",
		Timeout:      200 * time.Millisecond, // Ajustado localmente por config a un límite agresivo.
	}

	ctx := context.Background()

	t.Run("aborts eagerly on web delays", func(t *testing.T) {
		// La API tarda 1s, el timeout de seguridad está en 200ms
		_, err := resolver.Resolve(ctx, ResolverInput{})

		if err == nil {
			t.Errorf("expected Timeout Error, got none (DoS Vulnerability)")
		}

		if !strings.Contains(err.Error(), "Timeout") && !strings.Contains(err.Error(), "context deadline exceeded") && !strings.Contains(err.Error(), "webhook transport failed") {
			t.Errorf("Expected transport deadline error form client, got: %v", err)
		}
	})
}
