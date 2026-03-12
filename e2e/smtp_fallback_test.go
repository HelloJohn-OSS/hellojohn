//go:build integration

package e2e

import (
	"net/http"
	"strings"
	"testing"
)

// TestSMTPFallback verifica el comportamiento del sistema cuando el SMTP
// del tenant está/no está configurado.
//
// Estos tests son principalmente de smoke: verifican que el endpoint responde
// con un status code coherente (no 500 por panic) sin un servidor SMTP real.
func TestSMTPFallback(t *testing.T) {
	base := testBaseURL(t)

	t.Run("sin_smtp_alguno_no_panic", func(t *testing.T) {
		// Intentar reset de contraseña en un tenant inexistente.
		// Esperamos un 4xx (tenant not found o bad request), nunca un 5xx inesperado.
		body := strings.NewReader(`{"email":"test@example.com"}`)
		resp, err := http.Post(base+"/t/nonexistent-tenant/v2/auth/forgot-password", "application/json", body)
		if err != nil {
			// Si el servidor no está corriendo, omitir el test.
			t.Skipf("servidor no disponible: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 500 {
			t.Errorf("esperaba 4xx, got %d — posible panic en SMTP fallback", resp.StatusCode)
		}
		t.Logf("forgot-password (tenant inexistente) → %d ✓", resp.StatusCode)
	})

	t.Run("health_check_disponible", func(t *testing.T) {
		resp, err := http.Get(base + "/readyz")
		if err != nil {
			t.Skipf("servidor no disponible: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("readyz check: esperaba 200, got %d", resp.StatusCode)
		}
		t.Logf("readyz → %d ✓", resp.StatusCode)
	})
}
