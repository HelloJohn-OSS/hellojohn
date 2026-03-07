//go:build integration

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestMAUTracking verifica la idempotencia del tracking de MAU en la base de datos global.
//
// NOTA: El schema real usa    tenant_id UUID    (no tenant_slug).
// La columna month es DATE    (primer día del mes: 'YYYY-MM-01').
//
// El test usa t.Cleanup() para borrar los datos insertados.
// Si las tablas no existen (entorno sin migraciones) os subtests se omiten.
func TestMAUTracking(t *testing.T) {
	db := testGlobalDB(t)
	ctx := context.Background()

	// Usar un tenant_id único para no interferir con datos existentes.
	testTenantID := uuid.New()
	// Primer día del mes actual (formato DATE).
	now := time.Now().UTC()
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	monthStr := month.Format("2006-01-02")

	// Verificar que las tablas existen antes de proceder.
	var tableExists bool
	err := db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'tenant_usage')`,
	).Scan(&tableExists)
	if err != nil || !tableExists {
		t.Skipf("tabla tenant_usage no existe — omitiendo (ejecutar migraciones primero): %v", err)
	}

	t.Cleanup(func() {
		// Limpiar datos de test en orden correcto (FK)
		db.ExecContext(ctx,
			`DELETE FROM mau_unique_users WHERE tenant_id = $1 AND month = $2`,
			testTenantID, monthStr,
		)
		db.ExecContext(ctx,
			`DELETE FROM tenant_usage WHERE tenant_id = $1 AND month = $2`,
			testTenantID, monthStr,
		)
	})

	t.Run("insertar_registro_mau_inicial", func(t *testing.T) {
		_, err := db.ExecContext(ctx, `
			INSERT INTO tenant_usage (tenant_id, month, mau, total_logins)
			VALUES ($1, $2, 1, 1)
			ON CONFLICT (tenant_id, month) DO UPDATE
			SET mau = tenant_usage.mau + 1,
			    total_logins = tenant_usage.total_logins + 1,
			    updated_at = now()
		`, testTenantID, monthStr)
		if err != nil {
			t.Fatalf("insertar tenant_usage: %v", err)
		}
		t.Logf("INSERT tenant_usage tenant_id=%s month=%s ✓", testTenantID, monthStr)
	})

	t.Run("idempotencia_mismo_usuario_mismo_mes", func(t *testing.T) {
		userID := uuid.New().String()

		insertUnique := func() (int64, error) {
			res, err := db.ExecContext(ctx, `
				INSERT INTO mau_unique_users (tenant_id, month, user_id, first_seen_at)
				VALUES ($1, $2, $3, now())
				ON CONFLICT (tenant_id, month, user_id) DO NOTHING
			`, testTenantID, monthStr, userID)
			if err != nil {
				return 0, err
			}
			return res.RowsAffected()
		}

		// Primera inserción → 1 fila afectada
		rows, err := insertUnique()
		if err != nil {
			t.Fatalf("primera insercion: %v", err)
		}
		if rows != 1 {
			t.Errorf("primera insercion: esperaba 1 fila, got %d", rows)
		}

		// Segunda inserción del mismo usuario → 0 filas afectadas (ON CONFLICT DO NOTHING)
		rows, err = insertUnique()
		if err != nil {
			t.Fatalf("segunda insercion: %v", err)
		}
		if rows != 0 {
			t.Errorf("idempotencia: segunda insercion deberia afectar 0 filas, got %d", rows)
		}

		// Contar registros únicos para este tenant/mes
		var count int
		err = db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM mau_unique_users WHERE tenant_id = $1 AND month = $2`,
			testTenantID, monthStr,
		).Scan(&count)
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		if count != 1 {
			t.Errorf("esperaba 1 usuario único, got %d", count)
		}
		t.Logf("idempotencia MAU: user_id=%s mes=%s count=%d ✓", userID[:8], monthStr, count)
	})

	t.Run("usuarios_distintos_cuentan_separados", func(t *testing.T) {
		user1 := uuid.New().String()
		user2 := uuid.New().String()

		for _, uid := range []string{user1, user2} {
			_, err := db.ExecContext(ctx, `
				INSERT INTO mau_unique_users (tenant_id, month, user_id, first_seen_at)
				VALUES ($1, $2, $3, now())
				ON CONFLICT (tenant_id, month, user_id) DO NOTHING
			`, testTenantID, monthStr, uid)
			if err != nil {
				t.Fatalf("insertar usuario %s: %v", uid[:8], err)
			}
		}

		var count int
		err = db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM mau_unique_users WHERE tenant_id = $1 AND month = $2`,
			testTenantID, monthStr,
		).Scan(&count)
		if err != nil {
			t.Fatalf("count: %v", err)
		}
		// Puede haber el usuario del subtest anterior + estos 2
		if count < 2 {
			t.Errorf("esperaba >= 2 usuarios únicos, got %d", count)
		}
		t.Logf("usuarios distintos: count=%d ✓", count)
	})
}
