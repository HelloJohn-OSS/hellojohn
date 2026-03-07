package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/dropDatabas3/hellojohn/cmd/tools"
	"github.com/dropDatabas3/hellojohn/internal/bootstrap"
	v2server "github.com/dropDatabas3/hellojohn/internal/http/server"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	"github.com/joho/godotenv"

	_ "github.com/dropDatabas3/hellojohn/internal/store/adapters/dal"
)

// parsePortFlag scans os.Args for -port/-p <N> and returns the value (0 = not set).
func parsePortFlag() int {
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "-port" || arg == "-p" || arg == "--port" {
			if i+1 < len(os.Args) {
				if v, err := strconv.Atoi(os.Args[i+1]); err == nil {
					return v
				}
			}
		}
	}
	return 0
}

func main() {
	portFlag := parsePortFlag()

	log.Print("\n  _   _      _ _           _       _           \n | | | | ___| | | ___     | | ___ | |__  _ __  \n | |_| |/ _ \\ | |/ _ \\    | |/ _ \\| '_ \\| '_ \\ \n |  _  |  __/ | | (_) |  _| | (_) | | | | | | |\n |_| |_|\\___|_|_|\\___/  |___|\\___/|_| |_|_| |_|\n")
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Printf("No .env file found or error loading it: %v", err)
		log.Println("Continuing with system environment variables...")
	}

	ctx := context.Background()

	// ─── Detección de subcomandos CLI (antes de iniciar el servidor HTTP) ───
	if len(os.Args) > 1 && os.Args[1] == "sync-fs-to-db" {
		fsRoot := os.Getenv("FS_ROOT")
		if fsRoot == "" {
			fsRoot = "data"
		}
		globalDSN := os.Getenv("GLOBAL_DB_DSN")
		if globalDSN == "" {
			fmt.Fprintln(os.Stderr, "sync-fs-to-db: GLOBAL_DB_DSN is required")
			os.Exit(1)
		}
		globalDriver := os.Getenv("GLOBAL_DB_DRIVER")
		if globalDriver == "" {
			globalDriver = "pg"
		}
		syncCfg := store.SyncConfig{
			FSRoot:       fsRoot,
			GlobalDSN:    globalDSN,
			GlobalDriver: globalDriver,
			DryRun:       os.Getenv("SYNC_DRY_RUN") == "true",
			Logger:       log.Default(),
		}
		tools.RunSync(ctx, syncCfg)
		os.Exit(0)
	}

	v2Addr := os.Getenv("V2_SERVER_ADDR")
	if v2Addr == "" {
		v2Addr = ":8080"
	}
	if portFlag > 0 {
		v2Addr = fmt.Sprintf(":%d", portFlag)
	}

	log.Printf("Starting Server on %s", v2Addr)

	// Build V2 handler and dependencies
	v2h, v2cleanup, dal, err := v2server.BuildV2HandlerWithDeps()
	if err != nil {
		log.Fatalf("Wiring failed: %v", err)
	}
	defer func() {
		if err := v2cleanup(); err != nil {
			log.Printf("Cleanup error: %v", err)
		}
	}()

	// Admin Bootstrap: Check if admin users exist, prompt if needed
	if bootstrap.ShouldRunBootstrap(ctx, dal) {
		log.Print("\n               ,      \t\n     __  _.-´´` `'-.   \n    /||\\'._ __{}_(\t\n    ||||  |'--.__\\   \t\n    |  L.(   ^_\\^\t   \t\n    \\ .-' |   _ |\t    \n    | |   )\\___/\t    \n    |  \\-'`:._]\t    \n    \\__/;      '-.\t")

		if err := bootstrap.CheckAndCreateAdmin(ctx, bootstrap.AdminBootstrapConfig{
			DAL: dal,
		}); err != nil {
			log.Printf("   Admin bootstrap failed: %v", err)
			log.Println("   You can create an admin user later using: ./hellojohn admin:create")
		}

		log.Print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	}

	log.Printf("✅ V2 Server ready at %s", v2Addr)

	srv := &http.Server{
		Addr:         v2Addr,
		Handler:      v2h,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("    Server failed: %v", err)
	}
}
