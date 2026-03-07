package mysql_test

import (
	"context"
	"testing"

	"github.com/dropDatabas3/hellojohn/internal/store"
	_ "github.com/dropDatabas3/hellojohn/internal/store/adapters/mysql"
)

func TestMySQLAdapterRegistered(t *testing.T) {
	// Verificar que el adapter MySQL está registrado
	adapter, ok := store.GetAdapter("mysql")
	if !ok || adapter == nil {
		t.Fatal("MySQL adapter not registered")
	}

	if adapter.Name() != "mysql" {
		t.Errorf("Expected adapter name 'mysql', got '%s'", adapter.Name())
	}

	t.Log("MySQL adapter registered successfully")
}

func TestMySQLAdapterConnectRequiresDSN(t *testing.T) {
	adapter, ok := store.GetAdapter("mysql")
	if !ok || adapter == nil {
		t.Fatal("MySQL adapter not registered")
	}

	// Intentar conectar sin DSN debería fallar
	ctx := context.Background()
	_, err := adapter.Connect(ctx, store.AdapterConfig{})
	if err == nil {
		t.Error("Expected error when connecting without DSN")
	}

	t.Logf("Got expected error: %v", err)
}
