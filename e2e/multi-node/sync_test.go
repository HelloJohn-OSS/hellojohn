//go:build e2e

// e2e/multi-node/sync_test.go
// Tests de consistencia multi-nodo para EPIC 008.
// Requieren docker con los servicios levantados (make test-e2e-multinode).
//
// Ejecutar: go test -v -tags e2e ./e2e/multi-node/... -timeout 120s
// NO se ejecutan en: go test ./... (build tag e2e requerido)
package multinode_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"testing"
	"time"
)

const (
	nodeA = "http://localhost:8080"
	nodeB = "http://localhost:8081"
)

// TestWriteNodeA_ReadNodeB verifica que una escritura en nodo A es inmediatamente
// visible desde nodo B. Demuestra que ambos nodos leen de la misma Global DB.
func TestWriteNodeA_ReadNodeB(t *testing.T) {
	// 1. Crear un tenant en nodo A con slug único
	tenantSlug := fmt.Sprintf("e2e-tenant-%d", time.Now().Unix())
	body, _ := json.Marshal(map[string]string{
		"slug": tenantSlug,
		"name": "E2E Multi-Node Tenant",
	})

	resp, err := http.Post(nodeA+"/v2/admin/tenants", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("write to node A: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("write to node A: got %d, want 201", resp.StatusCode)
	}

	// 2. Leer inmediatamente desde nodo B — sin esperar.
	// La DB es la fuente de verdad, ambos nodos la consultan directamente.
	resp2, err := http.Get(nodeB + "/v2/admin/tenants/" + tenantSlug)
	if err != nil {
		t.Fatalf("read from node B: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("read from node B: got %d, want 200", resp2.StatusCode)
	}

	var result map[string]any
	if err := json.NewDecoder(resp2.Body).Decode(&result); err != nil {
		t.Fatalf("decode response from node B: %v", err)
	}
	if result["slug"] != tenantSlug {
		t.Errorf("node B returned wrong slug: got %v, want %q", result["slug"], tenantSlug)
	}
}

// TestDBDown_ReadsFallback verifica que cuando la DB se cae, los nodos siguen
// respondiendo lecturas con datos del caché FS (HTTP 200).
//
// Pre-condición: el tenant "acme" debe existir en el FS compartido.
// El test hace t.Skip si no se cumple (en lugar de fallar con error confuso).
func TestDBDown_ReadsFallback(t *testing.T) {
	// 1. Verificar que funciona con DB UP
	resp, err := http.Get(nodeA + "/v2/admin/tenants/acme")
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		t.Skip("pre-condition: tenant 'acme' not found via node A, skip fallback test")
	}
	resp.Body.Close()

	// 2. Bajar la DB (pause container — congela sin matar datos)
	if err := exec.Command("docker", "compose", "-f", "docker-compose.yml", "pause", "db").Run(); err != nil {
		t.Fatalf("pause db: %v", err)
	}
	defer exec.Command("docker", "compose", "-f", "docker-compose.yml", "unpause", "db").Run() //nolint:errcheck

	// Esperar que los nodos detecten la caída
	time.Sleep(2 * time.Second)

	// 3. Verificar que lecturas siguen funcionando desde caché FS (HTTP 200)
	for _, node := range []string{nodeA, nodeB} {
		r, err := http.Get(node + "/v2/admin/tenants/acme")
		if err != nil {
			t.Errorf("%s: request error with DB down: %v", node, err)
			continue
		}
		r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Errorf("%s: got %d with DB down, want 200 (FS fallback)", node, r.StatusCode)
		}
	}
}

// TestDBDown_WritesReturn503 verifica que cuando la DB se cae, las escrituras
// retornan HTTP 503 (Service Unavailable), no 200 ni 500.
//
// La capa de error HTTP mapea store.ErrDBUnavailable → 503 (via mapTenantError).
func TestDBDown_WritesReturn503(t *testing.T) {
	// 1. Bajar la DB
	if err := exec.Command("docker", "compose", "-f", "docker-compose.yml", "pause", "db").Run(); err != nil {
		t.Fatalf("pause db: %v", err)
	}
	defer exec.Command("docker", "compose", "-f", "docker-compose.yml", "unpause", "db").Run() //nolint:errcheck

	time.Sleep(2 * time.Second)

	// 2. Intentar escritura — debe fallar con 503
	body, _ := json.Marshal(map[string]string{
		"slug": "db-down-write-test",
		"name": "Should Return 503",
	})
	resp, err := http.Post(nodeA+"/v2/admin/tenants", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("write with DB down: %v", err)
	}
	defer resp.Body.Close()

	// 503 = DB unavailable (mapeo de store.ErrDBUnavailable → httperrors.ErrServiceUnavailable)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("write with DB down: got %d, want 503", resp.StatusCode)
	}
}
