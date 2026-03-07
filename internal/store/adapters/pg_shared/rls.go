package pg_shared

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// execWithRLS executes fn inside a transaction with SET LOCAL app.tenant_id.
// This activates RLS policies for the duration of the transaction.
//
// SET LOCAL is transaction-scoped. When the tx commits/rollbacks, the setting
// disappears automatically — no risk of leaking between requests.
//
// SECURITY MODEL:
//   - Reads: use r.pool.QueryRow/Query directly with WHERE tenant_id = $X clause.
//     The app DB user is the table owner; non-forced RLS is bypassed by owners.
//     The WHERE clause is the primary isolation layer for reads.
//   - Writes: MUST use execWithRLS (this function) for INSERT/UPDATE/DELETE.
//     The set_config call activates RLS policies as a DB-level second defense.
//
// NOTE: All GDP tables are created with FORCE ROW LEVEL SECURITY so that RLS
// policies apply even when the application DB user is the table owner.
// This function activates the per-transaction app.tenant_id setting which is
// the condition evaluated by every RLS policy. Non-owner roles used for read
// replicas or future role splits also benefit from this protection.
func execWithRLS(ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID, fn func(pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pg_shared: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// set_config() is preferred over SET LOCAL for cross-PG-version compatibility
	// with the extended query protocol. Third arg true = LOCAL (transaction-scoped).
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID.String()); err != nil {
		return fmt.Errorf("pg_shared: set rls tenant_id: %w", err)
	}

	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit(ctx)
}
