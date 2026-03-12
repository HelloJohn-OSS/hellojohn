//go:build integration

package e2e

import (
	"os/exec"
	"strings"
	"testing"
)

// TestOSSBuildPurity verifica que el binario OSS (sin tag "cloud") no incluye
// ningún paquete exclusivo del build cloud.
//
// Esto garantiza que la separación OSS/Cloud vía build tags funciona correctamente.
func TestOSSBuildPurity(t *testing.T) {
	// Paquetes que NO deben aparecer en un build OSS.
	// Solo incluir paquetes con //go:build cloud confirmado.
	forbiddenPackages := []string{
		"internal/billing",
	}

	// go list -deps usando import path completo del módulo (funciona desde cualquier directorio dentro del módulo)
	cmd := exec.Command("go", "list", "-deps", "github.com/dropDatabas3/hellojohn/cmd/service")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list -deps github.com/dropDatabas3/hellojohn/cmd/service: %v\noutput: %s", err, output)
	}

	deps := string(output)

	for _, pkg := range forbiddenPackages {
		if strings.Contains(deps, pkg) {
			t.Errorf("OSS build contiene paquete cloud-only: %q", pkg)
		}
	}

	if !t.Failed() {
		t.Logf("OSS build purity: OK — ningún paquete cloud-only encontrado ✓")
	}
}

// TestCloudBuildIncludes verifica que el binario cloud (con tag "cloud") SÍ incluye
// los paquetes exclusivos cloud que deben estar presentes.
func TestCloudBuildIncludes(t *testing.T) {
	// Paquetes que DEBEN aparecer en un build cloud.
	requiredPackages := []string{
		"internal/billing",
	}

	// En repositorios OSS puros, estos paquetes pueden no existir.
	// En ese caso, el check cloud-only no aplica.
	if err := exec.Command("go", "list", "-tags", "cloud", "github.com/dropDatabas3/hellojohn/internal/billing").Run(); err != nil {
		t.Skipf("cloud-only packages not available in this repository: %v", err)
	}

	// go list -deps con tags cloud, usando import path completo
	cmd := exec.Command("go", "list", "-tags", "cloud", "-deps", "github.com/dropDatabas3/hellojohn/cmd/service")
	output, err := cmd.Output()
	if err != nil {
		// En entornos sin los archivos cloud puede fallar — omitir
		t.Skipf("go list -tags cloud falló (posiblemente build cloud no disponible): %v", err)
	}

	deps := string(output)

	for _, pkg := range requiredPackages {
		if !strings.Contains(deps, pkg) {
			t.Errorf("cloud build NO contiene paquete esperado: %q", pkg)
		}
	}

	if !t.Failed() {
		t.Logf("cloud build includes: OK — paquetes cloud-only presentes ✓")
	}
}
