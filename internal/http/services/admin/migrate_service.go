package admin

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"sync"

	"github.com/dropDatabas3/hellojohn/internal/controlplane"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// MigrateService errors.
var (
	ErrMigrateTenantNotOnGDP = errors.New("tenant is not on the Global Data Plane")
	ErrMigrateDSNEmpty       = errors.New("target DSN is required")
	ErrMigrateAlreadyRunning = errors.New("migration already in progress for this tenant")
	// ErrMigrateETLNotImplemented is returned after a successful schema migration to signal
	// that user data (app_user, identity, refresh_token, rbac_*, etc.) was NOT copied to the
	// new isolated database. Callers MUST surface this to the operator — data lives on the GDP.
	ErrMigrateETLNotImplemented = errors.New("schema migration applied but data migration (ETL) is not yet implemented; users must be re-imported manually")
)

// MigrateService handles migration of tenants from Global Data Plane to isolated DB.
type MigrateService interface {
	// MigrateToIsolatedDB initiates migration of a tenant from GDP to an isolated database.
	// Steps (MVP):
	//  1. Validate tenant is on GDP (no own UserDB)
	//  2. Set MigratingToDSN lock (middleware returns 503)
	//  3. Connect to target, run schema migrations
	//  4. Update tenant settings with new UserDB
	//  5. Invalidate cache
	//  6. Clear lock
	MigrateToIsolatedDB(ctx context.Context, tenantSlug, targetDSN, driver string) error
}

// MigrateServiceDeps dependencies for the migrate service.
type MigrateServiceDeps struct {
	DAL              store.DataAccessLayer
	ControlPlane     controlplane.Service
	TenantMigrations embed.FS // Tenant schema migrations (isolated DB format)
	TenantMigrDir    string   // Directory within TenantMigrations FS
}

type migrateService struct {
	deps MigrateServiceDeps
	// locks serialises concurrent migration attempts per tenant (L-BACK-2: moved from package-level
	// to avoid cross-test interference when the same process runs multiple tests).
	locks sync.Map
}

// NewMigrateService creates a new migrate service.
func NewMigrateService(deps MigrateServiceDeps) MigrateService {
	return &migrateService{deps: deps}
}

func (s *migrateService) MigrateToIsolatedDB(ctx context.Context, tenantSlug, targetDSN, driver string) error {
	if targetDSN == "" {
		return ErrMigrateDSNEmpty
	}
	if driver == "" {
		driver = "postgres"
	}

	// 1. Resolve tenant
	tda, err := s.deps.DAL.ForTenant(ctx, tenantSlug)
	if err != nil {
		return fmt.Errorf("resolve tenant: %w", err)
	}

	// Verify tenant is on GDP (no own UserDB configured)
	settings := tda.Settings()
	if settings == nil {
		return ErrMigrateTenantNotOnGDP
	}
	if settings.UserDB != nil && settings.UserDB.Driver != "" {
		return ErrMigrateTenantNotOnGDP
	}

	// GDP-H3: Serialize concurrent migration attempts per tenant using an in-process lock.
	// This prevents the TOCTOU window between the MigratingToDSN check and the lock-set write.
	if _, loaded := s.locks.LoadOrStore(tda.Slug(), true); loaded {
		return ErrMigrateAlreadyRunning
	}
	defer s.locks.Delete(tda.Slug())

	if settings.MigratingToDSN != "" {
		return ErrMigrateAlreadyRunning
	}

	// 2. Set migration lock
	settingsCopy := *settings
	settingsCopy.MigratingToDSN = targetDSN
	if err := s.deps.ControlPlane.UpdateTenantSettings(ctx, tda.Slug(), &settingsCopy); err != nil {
		return fmt.Errorf("set migration lock: %w", err)
	}

	// 3. Connect to target and run isolated schema migrations
	targetConn, err := store.OpenAdapter(ctx, store.AdapterConfig{
		Name: driver,
		DSN:  targetDSN,
	})
	if err != nil {
		// Cleanup lock on failure
		s.clearMigrationLock(ctx, tda.Slug(), settings)
		return fmt.Errorf("connect to target DB: %w", err)
	}
	defer targetConn.Close()

	// Run tenant schema migrations on the TARGET isolated DB
	if mc, ok := targetConn.(store.MigratableConnection); ok {
		executor := mc.GetMigrationExecutor()
		if executor != nil && s.deps.TenantMigrDir != "" {
			migrator := store.NewMigrator(s.deps.TenantMigrations, s.deps.TenantMigrDir)
			result, err := migrator.RunWithPgxPool(ctx, executor)
			if err != nil {
				s.clearMigrationLock(ctx, tda.Slug(), settings)
				return fmt.Errorf("run migrations on target DB: %w", err)
			}
			if result != nil && len(result.Applied) > 0 {
				logger.From(ctx).Info("migrate-to-isolated: migrations applied",
					logger.String("tenant", tda.Slug()),
					logger.Int("count", len(result.Applied)),
				)
			}
		}
	} else {
		s.clearMigrationLock(ctx, tda.Slug(), settings)
		return fmt.Errorf("target adapter %q does not support schema migration; aborting", driver)
	}

	// 4. Update tenant settings with new UserDB
	// targetDSN is passed as plain-text; UpdateTenantSettings (controlplane/service.go)
	// will encrypt both UserDB.DSN → UserDB.DSNEnc and MigratingToDSN before writing
	// to disk. No plaintext DSN is ever persisted in tenant.yaml.
	settingsCopy.UserDB = &repository.UserDBSettings{
		Driver: driver,
		DSN:    targetDSN,
	}
	settingsCopy.MigratingToDSN = "" // Clear lock
	if err := s.deps.ControlPlane.UpdateTenantSettings(ctx, tda.Slug(), &settingsCopy); err != nil {
		s.clearMigrationLock(ctx, tda.Slug(), settings)
		return fmt.Errorf("update tenant config: %w", err)
	}

	// 5. Invalidate cache
	s.deps.DAL.InvalidateTenantCache(tda.Slug())

	// NOTE: Data migration not implemented. User data (app_user, identity, refresh_token,
	// rbac_*, mfa_*, user_consent, sessions, etc.) remains in the Global Data Plane.
	// The caller (MigrateController) informs the client about this via the response.
	logger.From(ctx).Info("migrate-to-isolated: schema-only migration completed — user data NOT copied, manual ETL required",
		logger.String("tenant", tda.Slug()),
	)

	// GDP-H4: Return a sentinel error so callers can surface the ETL gap clearly.
	// Schema and config are updated successfully; this error is non-fatal but MUST be
	// relayed to the operator (HTTP 202 with warning body, not 200 OK).
	return ErrMigrateETLNotImplemented
}

func (s *migrateService) clearMigrationLock(ctx context.Context, slug string, original *repository.TenantSettings) {
	cp := *original
	cp.MigratingToDSN = ""
	if err := s.deps.ControlPlane.UpdateTenantSettings(ctx, slug, &cp); err != nil {
		// CRITICAL: If this fails, the tenant remains locked with MigratingToDSN != "".
		// Future migration attempts will return ErrMigrateAlreadyRunning.
		// Manual fix: edit the tenant.yaml file and remove the migrating_to_dsn field.
		logger.From(ctx).Error("migrate_service: failed to clear migration lock — MANUAL CLEANUP REQUIRED: remove migrating_to_dsn from tenant.yaml",
			logger.String("tenant", slug),
			logger.Err(err),
		)
	}
}
