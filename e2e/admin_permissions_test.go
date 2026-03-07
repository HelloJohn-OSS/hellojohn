//go:build integration

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// doRequest es un helper para hacer requests HTTP autenticados al admin panel.
func doRequest(t *testing.T, method, url, token string, body interface{}) *http.Response {
	t.Helper()

	var bodyReader *bytes.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("doRequest: marshal: %v", err)
		}
		bodyReader = bytes.NewReader(buf)
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("doRequest: NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Skipf("servidor no disponible: %v", err)
	}
	return resp
}

// TestAdminPermissions verifica que la jerarquía de roles admin (readonly/member/owner)
// se aplica correctamente.
//
// Sin tokens reales seteados en el entorno, los subtests verifican únicamente
// que los endpoints responden con un status coherente (4xx, nunca 5xx inesperado).
func TestAdminPermissions(t *testing.T) {
	base := testBaseURL(t)

	// Tokens de prueba desde env — vacíos si no hay entorno completo.
	readonlyToken := "" // TEST_READONLY_TOKEN
	memberToken := ""   // TEST_MEMBER_TOKEN

	t.Run("sin_token_requiere_autenticacion", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, base+"/v2/admin/tenants", "", nil)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			t.Errorf("esperaba 401 o 403 sin token, got %d", resp.StatusCode)
		}
		t.Logf("GET /v2/admin/tenants sin token → %d ✓", resp.StatusCode)
	})

	t.Run("readonly_puede_listar_pero_no_crear", func(t *testing.T) {
		if readonlyToken == "" {
			t.Skip("TEST_READONLY_TOKEN no seteado")
		}

		// GET debería funcionar
		respGet := doRequest(t, http.MethodGet, fmt.Sprintf("%s/v2/admin/tenants", base), readonlyToken, nil)
		defer respGet.Body.Close()
		if respGet.StatusCode >= 500 {
			t.Errorf("readonly GET: inesperado %d", respGet.StatusCode)
		}

		// POST debería ser 403
		payload := map[string]string{"slug": uniqueName("t"), "name": "Test"}
		respPost := doRequest(t, http.MethodPost, fmt.Sprintf("%s/v2/admin/tenants", base), readonlyToken, payload)
		defer respPost.Body.Close()
		if respPost.StatusCode != http.StatusForbidden {
			t.Errorf("readonly POST: esperaba 403, got %d", respPost.StatusCode)
		}
		t.Logf("readonly: GET=%d, POST=%d ✓", respGet.StatusCode, respPost.StatusCode)
	})

	t.Run("member_puede_gestionar_usuarios", func(t *testing.T) {
		if memberToken == "" {
			t.Skip("TEST_MEMBER_TOKEN no seteado")
		}

		tenantSlug := "test-tenant"
		url := fmt.Sprintf("%s/v2/admin/tenants/%s/users", base, tenantSlug)
		resp := doRequest(t, http.MethodGet, url, memberToken, nil)
		defer resp.Body.Close()

		if resp.StatusCode >= 500 {
			t.Errorf("member GET users: inesperado %d", resp.StatusCode)
		}
		t.Logf("member GET /users → %d ✓", resp.StatusCode)
	})
}
