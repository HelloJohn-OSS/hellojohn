// cmd/tools/sync.go
// Punto de entrada CLI del subcomando sync-fs-to-db.
// No llama os.Getenv() — recibe SyncConfig ya construido por main.go.
package tools

import (
	"context"
	"fmt"
	"log"
	"os"

	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// RunSync ejecuta la migración FS→DB y reporta el resultado.
// La cfg ya viene construida por main.go — sin os.Getenv aquí.
func RunSync(ctx context.Context, cfg store.SyncConfig) {
	if cfg.DryRun {
		log.Println("sync-fs-to-db: DRY RUN mode — no data will be written to DB")
	}

	result, err := store.RunSyncFS2DB(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sync-fs-to-db: fatal error: %v\n", err)
		os.Exit(1)
	}

	if len(result.Errors) > 0 {
		log.Printf("sync completed with %d error(s):", len(result.Errors))
		for _, e := range result.Errors {
			log.Printf("  - %s", e)
		}
	}

	mode := "real"
	if cfg.DryRun {
		mode = "dry-run"
	}

	fmt.Printf("\nSync complete [%s]:\n", mode)
	fmt.Printf("  Tenants processed : %d\n", result.TenantsProcessed)
	fmt.Printf("  Tenants skipped   : %d\n", result.TenantsSkipped)
	fmt.Printf("  Clients upserted  : %d\n", result.ClientsUpserted)
	fmt.Printf("  Scopes upserted   : %d\n", result.ScopesUpserted)
	fmt.Printf("  Claims upserted   : %d\n", result.ClaimsUpserted)
	fmt.Printf("  Admins upserted   : %d\n", result.AdminsUpserted)
	fmt.Printf("  Errors            : %d\n", len(result.Errors))

	if len(result.Errors) > 0 {
		os.Exit(2) // errores parciales — no fatal, pero exit != 0 para CI
	}
}
