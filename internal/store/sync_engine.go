// internal/store/sync_engine.go
// Motor de migración FS → Global DB. No llama os.Getenv().
package store

import (
	"context"
	"fmt"
	"log"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// SyncConfig parámetros para la migración FS → DB.
// Todos los valores llegan inyectados desde cmd/ — sin os.Getenv aquí.
type SyncConfig struct {
	FSRoot       string      // Path al directorio FS (ej: "data/hellojohn")
	GlobalDSN    string      // DSN de la Global DB destino
	GlobalDriver string      // "pg" o "mysql"
	DryRun       bool        // Si true: simula sin escribir en DB
	Logger       *log.Logger // nil = log.Default()
}

// SyncResult contadores del proceso de migración.
type SyncResult struct {
	TenantsProcessed int
	TenantsSkipped   int
	ClientsUpserted  int
	ScopesUpserted   int
	ClaimsUpserted   int
	AdminsUpserted   int
	Errors           []string
}

// RunSyncFS2DB migra todos los datos de configuración del FS a la Global DB.
// Es idempotente: puede ejecutarse múltiples veces sin crear duplicados.
// Los repos DB usan ON CONFLICT ... DO UPDATE en sus Create().
//
// Orden de escritura (FK constraints):
//
//	Tenants → Clients/Scopes/Claims (por tenant) → Admins
func RunSyncFS2DB(ctx context.Context, cfg SyncConfig) (*SyncResult, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}

	result := &SyncResult{}

	// 1. Conectar al FS
	fsConn, err := OpenAdapter(ctx, AdapterConfig{
		Name:   "fs",
		FSRoot: cfg.FSRoot,
	})
	if err != nil {
		return nil, fmt.Errorf("sync: connect FS at %q: %w", cfg.FSRoot, err)
	}
	defer fsConn.Close()

	// 2. Conectar a la Global DB
	dbConn, err := OpenAdapter(ctx, AdapterConfig{
		Name: cfg.GlobalDriver,
		DSN:  cfg.GlobalDSN,
	})
	if err != nil {
		return nil, fmt.Errorf("sync: connect Global DB (%s): %w", cfg.GlobalDriver, err)
	}
	defer dbConn.Close()

	// 3. Obtener raw FS repos (interfaz interna que expone tenantSlug en cada método)
	raw, ok := fsConn.(FSRawConnection)
	if !ok {
		return nil, fmt.Errorf("sync: FS adapter does not implement FSRawConnection")
	}

	// 4. Leer todos los tenants del FS
	fsTenants, err := fsConn.Tenants().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("sync: list FS tenants: %w", err)
	}
	logger.Printf("sync: found %d tenants in FS", len(fsTenants))

	dbTenantRepo := dbConn.Tenants()

	for _, tenant := range fsTenants {
		t := tenant // captura de loop
		logger.Printf("sync: processing tenant %q (ID: %s)", t.Slug, t.ID)

		if !cfg.DryRun {
			if err := dbTenantRepo.Create(ctx, &t); err != nil {
				msg := fmt.Sprintf("tenant %q: %v", t.Slug, err)
				result.Errors = append(result.Errors, msg)
				result.TenantsSkipped++
				logger.Printf("sync: SKIP tenant %s — %v", t.Slug, err)
				continue
			}
		}
		result.TenantsProcessed++

		// ── 4a. Sync clients para este tenant ──
		// CORRECTO: RawClients().List usa tenantSlug (no UUID)
		fsClients, err := raw.RawClients().List(ctx, t.Slug, "")
		if err != nil {
			logger.Printf("sync: list clients for %q: %v", t.Slug, err)
		} else {
			// CORRECTO: repo DB se construye con tenantID (UUID), no slug
			dbClientRepo := buildDBClientRepo(dbConn, t.ID)
			for _, c := range fsClients {
				if cfg.DryRun {
					result.ClientsUpserted++
					continue
				}
				input := repository.ClientInput{
					ClientID:     c.ClientID,
					Name:         c.Name,
					Type:         c.Type,
					RedirectURIs: c.RedirectURIs,
					Scopes:       c.Scopes,    // campo real: Scopes (no AllowedScopes)
					Secret:       c.SecretEnc, // copiar encrypted blob tal cual — NO re-encriptar
					AuthProfile:  c.AuthProfile,
					GrantTypes:   c.GrantTypes,
				}
				if _, err := dbClientRepo.Create(ctx, input); err != nil {
					result.Errors = append(result.Errors,
						fmt.Sprintf("tenant %q client %q: %v", t.Slug, c.ClientID, err))
					continue
				}
				result.ClientsUpserted++
			}
		}

		// ── 4b. Sync scopes — usa tenantSlug para FS ──
		fsScopes, err := raw.RawScopes().List(ctx, t.Slug)
		if err != nil {
			logger.Printf("sync: list scopes for %q: %v", t.Slug, err)
		} else {
			dbScopeRepo := buildDBScopeRepo(dbConn, t.ID)
			for _, s := range fsScopes {
				if cfg.DryRun {
					result.ScopesUpserted++
					continue
				}
				input := repository.ScopeInput{
					Name:        s.Name,
					Description: s.Description,
					DisplayName: s.DisplayName,
					Claims:      s.Claims,
					DependsOn:   s.DependsOn,
					System:      s.System,
				}
				if _, err := dbScopeRepo.Upsert(ctx, input); err != nil {
					result.Errors = append(result.Errors,
						fmt.Sprintf("tenant %q scope %q: %v", t.Slug, s.Name, err))
					continue
				}
				result.ScopesUpserted++
			}
		}

		// ── 4c. Sync claims — usa tenantSlug para FS ──
		fsClaims, err := raw.RawClaims().List(ctx, t.Slug)
		if err != nil {
			logger.Printf("sync: list claims for %q: %v", t.Slug, err)
		} else {
			dbClaimsRepo := buildDBClaimsRepo(dbConn, t.ID)
			for _, cl := range fsClaims {
				if cfg.DryRun {
					result.ClaimsUpserted++
					continue
				}
				input := repository.ClaimInput{
					Name:          cl.Name,
					Description:   cl.Description,
					Source:        cl.Source,
					Value:         cl.Value,
					AlwaysInclude: cl.AlwaysInclude,
					Scopes:        cl.Scopes,
					Enabled:       cl.Enabled,
					Required:      cl.Required,
					ConfigData:    cl.ConfigData,
				}
				if _, err := dbClaimsRepo.Create(ctx, input); err != nil {
					result.Errors = append(result.Errors,
						fmt.Sprintf("tenant %q claim %q: %v", t.Slug, cl.Name, err))
					continue
				}
				result.ClaimsUpserted++
			}
		}
	}

	// 5. Sync admins (cross-tenant, no necesitan tenantID)
	fsAdmins, err := fsConn.Admins().List(ctx, repository.AdminFilter{})
	if err != nil {
		logger.Printf("sync: list FS admins: %v", err)
	} else {
		dbAdminRepo := dbConn.Admins()
		for _, a := range fsAdmins {
			if cfg.DryRun {
				result.AdminsUpserted++
				continue
			}
			input := repository.CreateAdminInput{
				Email:        a.Email,
				Name:         a.Name,
				PasswordHash: a.PasswordHash,
				Type:         a.Type,         // campo real: Type (no Role)
				TenantAccess: a.TenantAccess, // migrado desde AssignedTenants
			}
			if _, err := dbAdminRepo.Create(ctx, input); err != nil {
				// ErrConflict = ya existe → no es error fatal (idempotencia)
				if err.Error() != "conflict: already exists" {
					result.Errors = append(result.Errors,
						fmt.Sprintf("admin %q: %v", a.Email, err))
				}
				continue
			}
			result.AdminsUpserted++
		}
	}

	if cfg.DryRun {
		logger.Printf("sync: DRY RUN — no changes written to DB")
	}
	logger.Printf("sync: DONE — tenants:%d clients:%d scopes:%d claims:%d admins:%d errors:%d",
		result.TenantsProcessed, result.ClientsUpserted, result.ScopesUpserted,
		result.ClaimsUpserted, result.AdminsUpserted, len(result.Errors))

	return result, nil
}

// ─── Helpers para construir repos DB con tenantID pre-inyectado ───

// buildDBClientRepo construye un repo de clients DB con tenantID pre-inyectado.
// Requiere que pgConnection/mysqlConnection expongan NewClientRepo(tenantID).
func buildDBClientRepo(conn AdapterConnection, tenantID string) repository.ClientRepository {
	type clientRepoBuilder interface {
		NewClientRepo(tenantID string) repository.ClientRepository
	}
	if b, ok := conn.(clientRepoBuilder); ok {
		return b.NewClientRepo(tenantID)
	}
	panic(fmt.Sprintf("sync: adapter %q does not implement NewClientRepo", conn.Name()))
}

// buildDBScopeRepo construye un repo de scopes DB con tenantID pre-inyectado.
func buildDBScopeRepo(conn AdapterConnection, tenantID string) repository.ScopeRepository {
	type scopeRepoBuilder interface {
		NewScopeRepo(tenantID string) repository.ScopeRepository
	}
	if b, ok := conn.(scopeRepoBuilder); ok {
		return b.NewScopeRepo(tenantID)
	}
	panic(fmt.Sprintf("sync: adapter %q does not implement NewScopeRepo", conn.Name()))
}

// buildDBClaimsRepo construye un repo de claims DB con tenantID pre-inyectado.
func buildDBClaimsRepo(conn AdapterConnection, tenantID string) repository.ClaimRepository {
	type claimsRepoBuilder interface {
		NewClaimsRepo(tenantID string) repository.ClaimRepository
	}
	if b, ok := conn.(claimsRepoBuilder); ok {
		return b.NewClaimsRepo(tenantID)
	}
	panic(fmt.Sprintf("sync: adapter %q does not implement NewClaimsRepo", conn.Name()))
}
