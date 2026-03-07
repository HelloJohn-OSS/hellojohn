// internal/store/adapters/pg/cp_claims_repo.go
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// cpClaimsRepo implementa repository.ClaimRepository sobre cp_claims_config.
// El tenantID (UUID) se inyecta al construir el repo.
type cpClaimsRepo struct {
	pool     *pgxpool.Pool
	tenantID string
}

func (r *cpClaimsRepo) Create(ctx context.Context, input repository.ClaimInput) (*repository.ClaimDefinition, error) {
	configJSON, err := json.Marshal(input.ConfigData)
	if err != nil {
		return nil, fmt.Errorf("cp_claims_repo: marshal config: %w", err)
	}
	scopes := input.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	id := uuid.NewString()
	const q = `
		INSERT INTO cp_claims_config
			(id, tenant_id, claim_name, description, source_type, config, scopes,
			 always_include, required, enabled, system, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, false, now(), now())
		ON CONFLICT (tenant_id, claim_name) DO UPDATE
		  SET description=$4, source_type=$5, config=$6, scopes=$7,
		      always_include=$8, required=$9, enabled=$10, updated_at=now()
		RETURNING id, tenant_id, claim_name, description, source_type, config,
		          scopes, always_include, required, enabled, system, created_at, updated_at`
	row := r.pool.QueryRow(ctx, q,
		id, r.tenantID, input.Name, input.Description,
		claimSourceType(input.Source), configJSON, scopes,
		input.AlwaysInclude, input.Required, input.Enabled)
	return r.scanRow(row)
}

func (r *cpClaimsRepo) Get(ctx context.Context, claimID string) (*repository.ClaimDefinition, error) {
	const q = `
		SELECT id, tenant_id, claim_name, description, source_type, config,
		       scopes, always_include, required, enabled, system, created_at, updated_at
		FROM cp_claims_config WHERE id = $1 AND tenant_id = $2`
	row := r.pool.QueryRow(ctx, q, claimID, r.tenantID)
	cl, err := r.scanRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cp_claims_repo: get: %w", err)
	}
	return cl, nil
}

func (r *cpClaimsRepo) GetByName(ctx context.Context, name string) (*repository.ClaimDefinition, error) {
	const q = `
		SELECT id, tenant_id, claim_name, description, source_type, config,
		       scopes, always_include, required, enabled, system, created_at, updated_at
		FROM cp_claims_config WHERE tenant_id = $1 AND claim_name = $2`
	row := r.pool.QueryRow(ctx, q, r.tenantID, name)
	cl, err := r.scanRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cp_claims_repo: get by name: %w", err)
	}
	return cl, nil
}

func (r *cpClaimsRepo) List(ctx context.Context) ([]repository.ClaimDefinition, error) {
	const q = `
		SELECT id, tenant_id, claim_name, description, source_type, config,
		       scopes, always_include, required, enabled, system, created_at, updated_at
		FROM cp_claims_config WHERE tenant_id = $1 AND claim_name != '__settings__'
		ORDER BY claim_name`
	rows, err := r.pool.Query(ctx, q, r.tenantID)
	if err != nil {
		return nil, fmt.Errorf("cp_claims_repo: list: %w", err)
	}
	defer rows.Close()

	var out []repository.ClaimDefinition
	for rows.Next() {
		cl, err := r.scanRow(rows)
		if err != nil {
			return nil, fmt.Errorf("cp_claims_repo: scan: %w", err)
		}
		out = append(out, *cl)
	}
	return out, rows.Err()
}

func (r *cpClaimsRepo) Update(ctx context.Context, claimID string, input repository.ClaimInput) (*repository.ClaimDefinition, error) {
	configJSON, err := json.Marshal(input.ConfigData)
	if err != nil {
		return nil, fmt.Errorf("cp_claims_repo: marshal config: %w", err)
	}
	scopes := input.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	const q = `
		UPDATE cp_claims_config
		SET description=$3, source_type=$4, config=$5, scopes=$6,
		    always_include=$7, required=$8, enabled=$9, updated_at=now()
		WHERE id=$1 AND tenant_id=$2
		RETURNING id, tenant_id, claim_name, description, source_type, config,
		          scopes, always_include, required, enabled, system, created_at, updated_at`
	row := r.pool.QueryRow(ctx, q,
		claimID, r.tenantID, input.Description,
		claimSourceType(input.Source), configJSON, scopes,
		input.AlwaysInclude, input.Required, input.Enabled)
	cl, err := r.scanRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cp_claims_repo: update: %w", err)
	}
	return cl, nil
}

func (r *cpClaimsRepo) Delete(ctx context.Context, claimID string) error {
	const q = `DELETE FROM cp_claims_config WHERE id = $1 AND tenant_id = $2`
	tag, err := r.pool.Exec(ctx, q, claimID, r.tenantID)
	if err != nil {
		return fmt.Errorf("cp_claims_repo: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

// GetStandardClaimsConfig retorna defaults para claims OIDC estándar.
// Los claims estándar no tienen filas en cp_claims_config por defecto.
func (r *cpClaimsRepo) GetStandardClaimsConfig(ctx context.Context) ([]repository.StandardClaimConfig, error) {
	standards := []repository.StandardClaimConfig{
		{ClaimName: "sub", Description: "Subject identifier", Enabled: true, Scope: "openid"},
		{ClaimName: "iss", Description: "Issuer", Enabled: true, Scope: "openid"},
		{ClaimName: "aud", Description: "Audience", Enabled: true, Scope: "openid"},
		{ClaimName: "exp", Description: "Expiration time", Enabled: true, Scope: "openid"},
		{ClaimName: "iat", Description: "Issued at", Enabled: true, Scope: "openid"},
		{ClaimName: "email", Description: "Email address", Enabled: false, Scope: "email"},
		{ClaimName: "name", Description: "Full name", Enabled: false, Scope: "profile"},
	}
	// Verificar overrides en DB (fila con source_type='standard_override')
	const q = `
		SELECT claim_name, enabled FROM cp_claims_config
		WHERE tenant_id = $1 AND system = true AND claim_name != '__settings__'`
	rows, err := r.pool.Query(ctx, q, r.tenantID)
	if err != nil {
		return standards, nil // Retornar defaults si hay error de DB
	}
	defer rows.Close()
	overrides := map[string]bool{}
	for rows.Next() {
		var name string
		var enabled bool
		if err := rows.Scan(&name, &enabled); err == nil {
			overrides[name] = enabled
		}
	}
	for i, s := range standards {
		if v, ok := overrides[s.ClaimName]; ok {
			standards[i].Enabled = v
		}
	}
	return standards, nil
}

func (r *cpClaimsRepo) SetStandardClaimEnabled(ctx context.Context, claimName string, enabled bool) error {
	id := uuid.NewString()
	const q = `
		INSERT INTO cp_claims_config
			(id, tenant_id, claim_name, description, source_type, config, scopes,
			 always_include, required, enabled, system, created_at, updated_at)
		VALUES ($1, $2, $3, '', 'static', '{}', '{}', false, false, $4, true, now(), now())
		ON CONFLICT (tenant_id, claim_name) DO UPDATE
		  SET enabled=$4, updated_at=now()`
	_, err := r.pool.Exec(ctx, q, id, r.tenantID, claimName, enabled)
	if err != nil {
		return fmt.Errorf("cp_claims_repo: set standard claim enabled: %w", err)
	}
	return nil
}

// GetSettings retorna los settings de claims del tenant.
// Se almacenan en una fila especial con claim_name='__settings__'.
func (r *cpClaimsRepo) GetSettings(ctx context.Context) (*repository.ClaimsSettings, error) {
	const q = `
		SELECT config, updated_at FROM cp_claims_config
		WHERE tenant_id = $1 AND claim_name = '__settings__'`
	var configJSON []byte
	s := &repository.ClaimsSettings{TenantID: r.tenantID}
	err := r.pool.QueryRow(ctx, q, r.tenantID).Scan(&configJSON, &s.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, nil // Defaults vacíos
	}
	if err != nil {
		return nil, fmt.Errorf("cp_claims_repo: get settings: %w", err)
	}
	_ = json.Unmarshal(configJSON, s)
	s.TenantID = r.tenantID
	return s, nil
}

func (r *cpClaimsRepo) UpdateSettings(ctx context.Context, input repository.ClaimsSettingsInput) (*repository.ClaimsSettings, error) {
	current, err := r.GetSettings(ctx)
	if err != nil {
		return nil, err
	}
	if input.IncludeInAccessToken != nil {
		current.IncludeInAccessToken = *input.IncludeInAccessToken
	}
	if input.UseNamespacedClaims != nil {
		current.UseNamespacedClaims = *input.UseNamespacedClaims
	}
	if input.NamespacePrefix != nil {
		current.NamespacePrefix = input.NamespacePrefix
	}
	configJSON, err := json.Marshal(current)
	if err != nil {
		return nil, fmt.Errorf("cp_claims_repo: marshal settings: %w", err)
	}
	id := uuid.NewString()
	const q = `
		INSERT INTO cp_claims_config
			(id, tenant_id, claim_name, description, source_type, config, scopes,
			 always_include, required, enabled, system, created_at, updated_at)
		VALUES ($1, $2, '__settings__', '', 'static', $3, '{}', false, false, true, true, now(), now())
		ON CONFLICT (tenant_id, claim_name) DO UPDATE
		  SET config=$3, updated_at=now()`
	_, err = r.pool.Exec(ctx, q, id, r.tenantID, configJSON)
	if err != nil {
		return nil, fmt.Errorf("cp_claims_repo: update settings: %w", err)
	}
	return current, nil
}

func (r *cpClaimsRepo) GetEnabledClaimsForScopes(ctx context.Context, scopes []string) ([]repository.ClaimDefinition, error) {
	if len(scopes) == 0 {
		return nil, nil
	}
	const q = `
		SELECT id, tenant_id, claim_name, description, source_type, config,
		       scopes, always_include, required, enabled, system, created_at, updated_at
		FROM cp_claims_config
		WHERE tenant_id=$1 AND enabled=true AND claim_name != '__settings__'
		  AND (always_include=true OR scopes && $2::text[])`
	rows, err := r.pool.Query(ctx, q, r.tenantID, scopes)
	if err != nil {
		return nil, fmt.Errorf("cp_claims_repo: get enabled for scopes: %w", err)
	}
	defer rows.Close()

	var out []repository.ClaimDefinition
	for rows.Next() {
		cl, err := r.scanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *cl)
	}
	return out, rows.Err()
}

// ─── helpers ───

func (r *cpClaimsRepo) scanRow(row interface {
	Scan(dest ...any) error
}) (*repository.ClaimDefinition, error) {
	var cl repository.ClaimDefinition
	var configJSON []byte
	var scopes []string
	err := row.Scan(
		&cl.ID, &cl.TenantID, &cl.Name, &cl.Description,
		&cl.Source, &configJSON, &scopes,
		&cl.AlwaysInclude, &cl.Required, &cl.Enabled, &cl.System,
		&cl.CreatedAt, &cl.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	cl.Scopes = scopes
	if len(configJSON) > 0 {
		_ = json.Unmarshal(configJSON, &cl.ConfigData)
	}
	return &cl, nil
}

// claimSourceType normaliza el campo Source de ClaimInput al enum de DB.
func claimSourceType(source string) string {
	if source == "" {
		return "static"
	}
	return source
}

// NewClaimsRepo construye un cpClaimsRepo con tenantID pre-inyectado.
func (c *pgConnection) NewClaimsRepo(tenantID string) repository.ClaimRepository {
	return &cpClaimsRepo{pool: c.pool, tenantID: tenantID}
}

// Verificación en compilación.
var _ repository.ClaimRepository = (*cpClaimsRepo)(nil)
