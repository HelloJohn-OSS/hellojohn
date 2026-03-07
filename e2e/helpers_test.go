//go:build integration

package e2e

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// testDB abre una conexión a la DB de test (tenant).
// La URL se toma de TEST_DATABASE_URL; si no está seteada, el test se omite.
func testDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL no seteada — omitiendo test de integración con DB")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("testDB: sql.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Fatalf("testDB: ping: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// testGlobalDB abre una conexión a la DB global del sistema.
// La URL se toma de TEST_GLOBAL_DB_URL; si no está seteada, el test se omite.
func testGlobalDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_GLOBAL_DB_URL")
	if dsn == "" {
		t.Skip("TEST_GLOBAL_DB_URL no seteada — omitiendo test de integración con global DB")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("testGlobalDB: sql.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Fatalf("testGlobalDB: ping: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// testBaseURL devuelve la URL base del servidor bajo test.
// Si TEST_BASE_URL no está seteada, usa "http://localhost:8080".
func testBaseURL(t *testing.T) string {
	t.Helper()
	if u := os.Getenv("TEST_BASE_URL"); u != "" {
		return u
	}
	return "http://localhost:8080"
}

// uniqueName genera un nombre único con el prefijo dado, usando los primeros 8 chars de un UUID v4.
func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%s", prefix, uuid.New().String()[:8])
}
