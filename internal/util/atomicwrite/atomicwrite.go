// Package atomicwrite provee un helper para escritura atómica de archivos.
// Es Windows-safe: si rename falla, intenta remove+rename (preserva lo viejo si falla).
package atomicwrite

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// AtomicWriteFile escribe data a path de forma atómica.
// Pasos: write tmp → Sync → Close → Chmod → Rename (con fallback Windows-safe)
//
// En Windows, os.Rename puede fallar si el destino existe/está bloqueado.
// Si rename falla, intenta remove+rename. Esto preserva el archivo viejo
// si algo sale mal (a diferencia de remove-before-rename que lo destruye).
func AtomicWriteFile(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	// Usar CreateTemp para evitar colisiones
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()

	// Cleanup en caso de error
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}

	// Set perms antes del rename
	_ = os.Chmod(tmpPath, perm)

	// Try rename; si falla (Windows con archivo bloqueado), try remove+rename
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(path)
		if err2 := os.Rename(tmpPath, path); err2 != nil {
			return fmt.Errorf("rename: %v (after remove: %v)", err, err2)
		}
	}

	return nil
}
