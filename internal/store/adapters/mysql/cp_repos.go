// internal/store/adapters/mysql/cp_repos.go
// Control Plane Repositories para MySQL 8.0+
// Equivalente funcional de los repos PG pero usando database/sql.
package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	gomysql "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/security/password"
	"github.com/dropDatabas3/hellojohn/internal/security/secretbox"
)

// isMySQLDuplicateEntry detecta violaciones de UNIQUE/PK constraint (error 1062).
func isMySQLDuplicateEntry(err error) bool {
	var mysqlErr *gomysql.MySQLError
	return errors.As(err, &mysqlErr) && mysqlErr.Number == 1062
}

// ═══════════════════════════════════════════════════════════════════════════════
// cpTenantRepoMySQL
// ═══════════════════════════════════════════════════════════════════════════════

type cpTenantRepoMySQL struct{ db *sql.DB }

func (r *cpTenantRepoMySQL) GetBySlug(ctx context.Context, slug string) (*repository.Tenant, error) {
	const q = `SELECT id, slug, name, language, settings, enabled, created_at, updated_at FROM cp_tenant WHERE slug=?`
	return r.scanOne(ctx, q, slug)
}

func (r *cpTenantRepoMySQL) GetByID(ctx context.Context, id string) (*repository.Tenant, error) {
	const q = `SELECT id, slug, name, language, settings, enabled, created_at, updated_at FROM cp_tenant WHERE id=?`
	return r.scanOne(ctx, q, id)
}

func (r *cpTenantRepoMySQL) List(ctx context.Context) ([]repository.Tenant, error) {
	const q = `SELECT id, slug, name, language, settings, enabled, created_at, updated_at FROM cp_tenant ORDER BY slug`
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("mysql_cp_tenant: list: %w", err)
	}
	defer rows.Close()
	var out []repository.Tenant
	for rows.Next() {
		t, err := scanMySQLTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func (r *cpTenantRepoMySQL) Create(ctx context.Context, tenant *repository.Tenant) error {
	settingsJSON, err := json.Marshal(tenant.Settings)
	if err != nil {
		return fmt.Errorf("mysql_cp_tenant: marshal: %w", err)
	}
	const q = `INSERT INTO cp_tenant (id, slug, name, language, settings, enabled, created_at, updated_at)
	            VALUES (?,?,?,?,?,1,NOW(6),NOW(6))`
	_, err = r.db.ExecContext(ctx, q, tenant.ID, tenant.Slug, tenant.Name, tenant.Language, settingsJSON)
	if err != nil {
		if isMySQLDuplicateEntry(err) {
			return repository.ErrConflict
		}
		return fmt.Errorf("mysql_cp_tenant: create: %w", err)
	}
	return nil
}

func (r *cpTenantRepoMySQL) Update(ctx context.Context, tenant *repository.Tenant) error {
	settingsJSON, err := json.Marshal(tenant.Settings)
	if err != nil {
		return fmt.Errorf("mysql_cp_tenant: marshal: %w", err)
	}
	const q = `UPDATE cp_tenant SET name=?,language=?,settings=?,updated_at=NOW(6) WHERE id=?`
	res, err := r.db.ExecContext(ctx, q, tenant.Name, tenant.Language, settingsJSON, tenant.ID)
	if err != nil {
		return fmt.Errorf("mysql_cp_tenant: update: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *cpTenantRepoMySQL) Delete(ctx context.Context, id string) error {
	const q = `DELETE FROM cp_tenant WHERE id=?`
	res, err := r.db.ExecContext(ctx, q, id)
	if err != nil {
		return fmt.Errorf("mysql_cp_tenant: delete: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *cpTenantRepoMySQL) UpdateSettings(ctx context.Context, id string, settings *repository.TenantSettings) error {
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("mysql_cp_tenant: marshal: %w", err)
	}
	const q = `UPDATE cp_tenant SET settings=?,updated_at=NOW(6) WHERE id=?`
	res, err := r.db.ExecContext(ctx, q, settingsJSON, id)
	if err != nil {
		return fmt.Errorf("mysql_cp_tenant: update settings: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *cpTenantRepoMySQL) scanOne(ctx context.Context, q string, args ...any) (*repository.Tenant, error) {
	row := r.db.QueryRowContext(ctx, q, args...)
	t, err := scanMySQLTenant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("mysql_cp_tenant: scan: %w", err)
	}
	return t, nil
}

func scanMySQLTenant(row interface {
	Scan(dest ...any) error
}) (*repository.Tenant, error) {
	var t repository.Tenant
	var settingsJSON []byte
	var enabled bool
	err := row.Scan(&t.ID, &t.Slug, &t.Name, &t.Language, &settingsJSON, &enabled, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if len(settingsJSON) > 0 {
		_ = json.Unmarshal(settingsJSON, &t.Settings)
	}
	return &t, nil
}

var _ repository.TenantRepository = (*cpTenantRepoMySQL)(nil)

// ═══════════════════════════════════════════════════════════════════════════════
// cpClientRepoMySQL
// ═══════════════════════════════════════════════════════════════════════════════

type cpClientRepoMySQL struct {
	db       *sql.DB
	tenantID string
}

const mysqlClientCols = `id, tenant_id, client_id, name, type, secret_enc, settings, redirect_uris, allowed_scopes, enabled, created_at, updated_at`

func (r *cpClientRepoMySQL) Get(ctx context.Context, clientID string) (*repository.Client, error) {
	q := `SELECT ` + mysqlClientCols + ` FROM cp_client WHERE tenant_id=? AND client_id=?`
	row := r.db.QueryRowContext(ctx, q, r.tenantID, clientID)
	c, err := scanMySQLClient(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("mysql_cp_client: get: %w", err)
	}
	return c, nil
}

func (r *cpClientRepoMySQL) GetByUUID(ctx context.Context, id string) (*repository.Client, *repository.ClientVersion, error) {
	q := `SELECT ` + mysqlClientCols + ` FROM cp_client WHERE id=?`
	row := r.db.QueryRowContext(ctx, q, id)
	c, err := scanMySQLClient(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("mysql_cp_client: get by uuid: %w", err)
	}
	return c, nil, nil
}

func (r *cpClientRepoMySQL) List(ctx context.Context, query string) ([]repository.Client, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if query != "" {
		q := `SELECT ` + mysqlClientCols + ` FROM cp_client WHERE tenant_id=? AND (name LIKE ? OR client_id LIKE ?) ORDER BY name`
		like := "%" + query + "%"
		rows, err = r.db.QueryContext(ctx, q, r.tenantID, like, like)
	} else {
		q := `SELECT ` + mysqlClientCols + ` FROM cp_client WHERE tenant_id=? ORDER BY name`
		rows, err = r.db.QueryContext(ctx, q, r.tenantID)
	}
	if err != nil {
		return nil, fmt.Errorf("mysql_cp_client: list: %w", err)
	}
	defer rows.Close()
	var out []repository.Client
	for rows.Next() {
		c, err := scanMySQLClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (r *cpClientRepoMySQL) Create(ctx context.Context, input repository.ClientInput) (*repository.Client, error) {
	settingsJSON, err := json.Marshal(buildMySQLClientSettings(input))
	if err != nil {
		return nil, fmt.Errorf("mysql_cp_client: marshal: %w", err)
	}
	redirectJSON, _ := json.Marshal(input.RedirectURIs)
	scopesJSON, _ := json.Marshal(input.Scopes)
	var secretEnc interface{}
	if input.Secret != "" {
		secretEnc = input.Secret
	}
	const q = `INSERT INTO cp_client
		(tenant_id,client_id,name,type,secret_enc,settings,redirect_uris,allowed_scopes,enabled,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?,1,NOW(6),NOW(6))`
	_, err = r.db.ExecContext(ctx, q,
		r.tenantID, input.ClientID, input.Name, input.Type,
		secretEnc, settingsJSON, redirectJSON, scopesJSON)
	if err != nil {
		if isMySQLDuplicateEntry(err) {
			return nil, repository.ErrConflict
		}
		return nil, fmt.Errorf("mysql_cp_client: create: %w", err)
	}
	return r.Get(ctx, input.ClientID)
}

func (r *cpClientRepoMySQL) Update(ctx context.Context, input repository.ClientInput) (*repository.Client, error) {
	settingsJSON, err := json.Marshal(buildMySQLClientSettings(input))
	if err != nil {
		return nil, fmt.Errorf("mysql_cp_client: marshal: %w", err)
	}
	redirectJSON, _ := json.Marshal(input.RedirectURIs)
	scopesJSON, _ := json.Marshal(input.Scopes)
	var secretEnc interface{}
	if input.Secret != "" {
		secretEnc = input.Secret
	}
	const q = `UPDATE cp_client
		SET name=?,type=?,secret_enc=COALESCE(?,secret_enc),settings=?,redirect_uris=?,allowed_scopes=?,updated_at=NOW(6)
		WHERE tenant_id=? AND client_id=?`
	res, err := r.db.ExecContext(ctx, q,
		input.Name, input.Type, secretEnc, settingsJSON, redirectJSON, scopesJSON,
		r.tenantID, input.ClientID)
	if err != nil {
		return nil, fmt.Errorf("mysql_cp_client: update: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, repository.ErrNotFound
	}
	return r.Get(ctx, input.ClientID)
}

func (r *cpClientRepoMySQL) Delete(ctx context.Context, clientID string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM cp_client WHERE tenant_id=? AND client_id=?`, r.tenantID, clientID)
	if err != nil {
		return fmt.Errorf("mysql_cp_client: delete: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *cpClientRepoMySQL) DecryptSecret(ctx context.Context, clientID string) (string, error) {
	var enc sql.NullString
	err := r.db.QueryRowContext(ctx, `SELECT secret_enc FROM cp_client WHERE tenant_id=? AND client_id=?`,
		r.tenantID, clientID).Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		return "", repository.ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if !enc.Valid || enc.String == "" {
		return "", nil
	}
	return secretbox.Decrypt(enc.String)
}

func (r *cpClientRepoMySQL) ValidateClientID(id string) bool { return len(id) >= 3 && len(id) <= 64 }

func (r *cpClientRepoMySQL) ValidateRedirectURI(uri string) bool {
	uri = strings.ToLower(strings.TrimSpace(uri))
	return strings.HasPrefix(uri, "https://") ||
		strings.HasPrefix(uri, "http://localhost") ||
		strings.HasPrefix(uri, "http://127.0.0.1")
}

func (r *cpClientRepoMySQL) IsScopeAllowed(client *repository.Client, scope string) bool {
	for _, s := range client.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func scanMySQLClient(row interface {
	Scan(dest ...any) error
}) (*repository.Client, error) {
	var (
		c            repository.Client
		pkID         string
		secretEnc    sql.NullString
		settingsJSON []byte
		redirectJSON []byte
		scopesJSON   []byte
		enabled      bool
		createdAt    time.Time
		updatedAt    time.Time
	)
	err := row.Scan(
		&pkID, &c.TenantID, &c.ClientID, &c.Name, &c.Type, &secretEnc,
		&settingsJSON, &redirectJSON, &scopesJSON,
		&enabled, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	c.ID = pkID
	if secretEnc.Valid {
		c.SecretEnc = secretEnc.String
	}
	_ = json.Unmarshal(redirectJSON, &c.RedirectURIs)
	_ = json.Unmarshal(scopesJSON, &c.Scopes)
	if len(settingsJSON) > 0 {
		applyClientSettings(&c, settingsJSON)
	}
	return &c, nil
}

func buildMySQLClientSettings(input repository.ClientInput) map[string]any {
	return map[string]any{
		"authProfile":              input.AuthProfile,
		"allowedOrigins":           input.AllowedOrigins,
		"providers":                input.Providers,
		"requireEmailVerification": input.RequireEmailVerification,
		"resetPasswordURL":         input.ResetPasswordURL,
		"verifyEmailURL":           input.VerifyEmailURL,
		"claimSchema":              input.ClaimSchema,
		"claimMapping":             input.ClaimMapping,
		"grantTypes":               input.GrantTypes,
		"accessTokenTTL":           input.AccessTokenTTL,
		"refreshTokenTTL":          input.RefreshTokenTTL,
		"idTokenTTL":               input.IDTokenTTL,
		"postLogoutURIs":           input.PostLogoutURIs,
		"description":              input.Description,
	}
}

// applyClientSettings reutilizada del paquete pg (misma firma, es un helper free).
// Redefinida acá para no crear dependencia entre packages.
func applyClientSettings(c *repository.Client, raw []byte) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return
	}
	applyString := func(key string, dst *string) {
		if v, ok := m[key].(string); ok {
			*dst = v
		}
	}
	applyBool := func(key string, dst *bool) {
		if v, ok := m[key].(bool); ok {
			*dst = v
		}
	}
	applyStringSlice := func(key string, dst *[]string) {
		if arr, ok := m[key].([]any); ok {
			for _, a := range arr {
				if s, ok := a.(string); ok {
					*dst = append(*dst, s)
				}
			}
		}
	}
	applyString("authProfile", &c.AuthProfile)
	applyString("description", &c.Description)
	applyString("resetPasswordURL", &c.ResetPasswordURL)
	applyString("verifyEmailURL", &c.VerifyEmailURL)
	applyBool("requireEmailVerification", &c.RequireEmailVerification)
	applyStringSlice("allowedOrigins", &c.AllowedOrigins)
	applyStringSlice("providers", &c.Providers)
	applyStringSlice("grantTypes", &c.GrantTypes)
	applyStringSlice("postLogoutURIs", &c.PostLogoutURIs)
	if v, ok := m["accessTokenTTL"].(float64); ok {
		c.AccessTokenTTL = int(v)
	}
	if v, ok := m["refreshTokenTTL"].(float64); ok {
		c.RefreshTokenTTL = int(v)
	}
	if v, ok := m["idTokenTTL"].(float64); ok {
		c.IDTokenTTL = int(v)
	}
}

var _ repository.ClientRepository = (*cpClientRepoMySQL)(nil)

// ═══════════════════════════════════════════════════════════════════════════════
// cpScopeRepoMySQL
// ═══════════════════════════════════════════════════════════════════════════════

type cpScopeRepoMySQL struct {
	db       *sql.DB
	tenantID string
}

func (r *cpScopeRepoMySQL) Create(ctx context.Context, input repository.ScopeInput) (*repository.Scope, error) {
	claimsJSON, _ := json.Marshal(input.Claims)
	const q = `INSERT INTO cp_scope (tenant_id,name,description,claims,system,created_at,updated_at)
	            VALUES (?,?,?,?,?,NOW(6),NOW(6))`
	_, err := r.db.ExecContext(ctx, q, r.tenantID, input.Name, input.Description, claimsJSON, input.System)
	if err != nil {
		if isMySQLDuplicate(err) {
			return nil, repository.ErrConflict
		}
		return nil, fmt.Errorf("mysql_cp_scope: create: %w", err)
	}
	return r.GetByName(ctx, input.Name)
}

func (r *cpScopeRepoMySQL) GetByName(ctx context.Context, name string) (*repository.Scope, error) {
	const q = `SELECT id,tenant_id,name,description,claims,system,created_at,updated_at FROM cp_scope WHERE tenant_id=? AND name=?`
	row := r.db.QueryRowContext(ctx, q, r.tenantID, name)
	s, err := scanMySQLScope(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	return s, err
}

func (r *cpScopeRepoMySQL) List(ctx context.Context) ([]repository.Scope, error) {
	const q = `SELECT id,tenant_id,name,description,claims,system,created_at,updated_at FROM cp_scope WHERE tenant_id=? ORDER BY name`
	rows, err := r.db.QueryContext(ctx, q, r.tenantID)
	if err != nil {
		return nil, fmt.Errorf("mysql_cp_scope: list: %w", err)
	}
	defer rows.Close()
	var out []repository.Scope
	for rows.Next() {
		s, err := scanMySQLScope(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

func (r *cpScopeRepoMySQL) Update(ctx context.Context, input repository.ScopeInput) (*repository.Scope, error) {
	claimsJSON, _ := json.Marshal(input.Claims)
	const q = `UPDATE cp_scope SET description=?,claims=?,system=?,updated_at=NOW(6) WHERE tenant_id=? AND name=?`
	res, err := r.db.ExecContext(ctx, q, input.Description, claimsJSON, input.System, r.tenantID, input.Name)
	if err != nil {
		return nil, fmt.Errorf("mysql_cp_scope: update: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, repository.ErrNotFound
	}
	return r.GetByName(ctx, input.Name)
}

func (r *cpScopeRepoMySQL) Delete(ctx context.Context, scopeID string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM cp_scope WHERE tenant_id=? AND name=?`, r.tenantID, scopeID)
	if err != nil {
		return fmt.Errorf("mysql_cp_scope: delete: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *cpScopeRepoMySQL) Upsert(ctx context.Context, input repository.ScopeInput) (*repository.Scope, error) {
	claimsJSON, _ := json.Marshal(input.Claims)
	const q = `INSERT INTO cp_scope (tenant_id,name,description,claims,system,created_at,updated_at)
	            VALUES (?,?,?,?,?,NOW(6),NOW(6))
	            ON DUPLICATE KEY UPDATE description=VALUES(description),claims=VALUES(claims),system=VALUES(system),updated_at=NOW(6)`
	_, err := r.db.ExecContext(ctx, q, r.tenantID, input.Name, input.Description, claimsJSON, input.System)
	if err != nil {
		return nil, fmt.Errorf("mysql_cp_scope: upsert: %w", err)
	}
	return r.GetByName(ctx, input.Name)
}

func scanMySQLScope(row interface {
	Scan(dest ...any) error
}) (*repository.Scope, error) {
	var s repository.Scope
	var claimsJSON []byte
	var updatedAt time.Time
	err := row.Scan(&s.ID, &s.TenantID, &s.Name, &s.Description, &claimsJSON, &s.System, &s.CreatedAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(claimsJSON, &s.Claims)
	s.UpdatedAt = &updatedAt
	return &s, nil
}

var _ repository.ScopeRepository = (*cpScopeRepoMySQL)(nil)

// ═══════════════════════════════════════════════════════════════════════════════
// cpClaimsRepoMySQL
// ═══════════════════════════════════════════════════════════════════════════════

type cpClaimsRepoMySQL struct {
	db       *sql.DB
	tenantID string
}

func (r *cpClaimsRepoMySQL) Create(ctx context.Context, input repository.ClaimInput) (*repository.ClaimDefinition, error) {
	configJSON, _ := json.Marshal(input.ConfigData)
	scopesJSON, _ := json.Marshal(input.Scopes)
	id := uuid.NewString()
	const q = `INSERT INTO cp_claims_config
		(id,tenant_id,claim_name,description,source_type,config,scopes,always_include,required,enabled,system,created_at,updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,0,NOW(6),NOW(6))
		ON DUPLICATE KEY UPDATE description=VALUES(description),source_type=VALUES(source_type),
		config=VALUES(config),scopes=VALUES(scopes),always_include=VALUES(always_include),
		required=VALUES(required),enabled=VALUES(enabled),updated_at=NOW(6)`
	_, err := r.db.ExecContext(ctx, q, id, r.tenantID, input.Name, input.Description,
		claimSourceTypeMySQL(input.Source), configJSON, scopesJSON,
		input.AlwaysInclude, input.Required, input.Enabled)
	if err != nil {
		return nil, fmt.Errorf("mysql_cp_claims: create: %w", err)
	}
	return r.GetByName(ctx, input.Name)
}

func (r *cpClaimsRepoMySQL) Get(ctx context.Context, claimID string) (*repository.ClaimDefinition, error) {
	const q = `SELECT id,tenant_id,claim_name,description,source_type,config,scopes,always_include,required,enabled,system,created_at,updated_at
	           FROM cp_claims_config WHERE id=? AND tenant_id=?`
	row := r.db.QueryRowContext(ctx, q, claimID, r.tenantID)
	cl, err := scanMySQLClaim(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	return cl, err
}

func (r *cpClaimsRepoMySQL) GetByName(ctx context.Context, name string) (*repository.ClaimDefinition, error) {
	const q = `SELECT id,tenant_id,claim_name,description,source_type,config,scopes,always_include,required,enabled,system,created_at,updated_at
	           FROM cp_claims_config WHERE tenant_id=? AND claim_name=?`
	row := r.db.QueryRowContext(ctx, q, r.tenantID, name)
	cl, err := scanMySQLClaim(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	return cl, err
}

func (r *cpClaimsRepoMySQL) List(ctx context.Context) ([]repository.ClaimDefinition, error) {
	const q = `SELECT id,tenant_id,claim_name,description,source_type,config,scopes,always_include,required,enabled,system,created_at,updated_at
	           FROM cp_claims_config WHERE tenant_id=? AND claim_name != '__settings__' ORDER BY claim_name`
	rows, err := r.db.QueryContext(ctx, q, r.tenantID)
	if err != nil {
		return nil, fmt.Errorf("mysql_cp_claims: list: %w", err)
	}
	defer rows.Close()
	var out []repository.ClaimDefinition
	for rows.Next() {
		cl, err := scanMySQLClaim(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *cl)
	}
	return out, rows.Err()
}

func (r *cpClaimsRepoMySQL) Update(ctx context.Context, claimID string, input repository.ClaimInput) (*repository.ClaimDefinition, error) {
	configJSON, _ := json.Marshal(input.ConfigData)
	scopesJSON, _ := json.Marshal(input.Scopes)
	const q = `UPDATE cp_claims_config
		SET description=?,source_type=?,config=?,scopes=?,always_include=?,required=?,enabled=?,updated_at=NOW(6)
		WHERE id=? AND tenant_id=?`
	res, err := r.db.ExecContext(ctx, q, input.Description, claimSourceTypeMySQL(input.Source),
		configJSON, scopesJSON, input.AlwaysInclude, input.Required, input.Enabled,
		claimID, r.tenantID)
	if err != nil {
		return nil, fmt.Errorf("mysql_cp_claims: update: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, repository.ErrNotFound
	}
	return r.Get(ctx, claimID)
}

func (r *cpClaimsRepoMySQL) Delete(ctx context.Context, claimID string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM cp_claims_config WHERE id=? AND tenant_id=?`, claimID, r.tenantID)
	if err != nil {
		return fmt.Errorf("mysql_cp_claims: delete: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *cpClaimsRepoMySQL) GetStandardClaimsConfig(ctx context.Context) ([]repository.StandardClaimConfig, error) {
	standards := []repository.StandardClaimConfig{
		{ClaimName: "sub", Description: "Subject identifier", Enabled: true, Scope: "openid"},
		{ClaimName: "iss", Description: "Issuer", Enabled: true, Scope: "openid"},
		{ClaimName: "aud", Description: "Audience", Enabled: true, Scope: "openid"},
		{ClaimName: "exp", Description: "Expiration time", Enabled: true, Scope: "openid"},
		{ClaimName: "iat", Description: "Issued at", Enabled: true, Scope: "openid"},
		{ClaimName: "email", Description: "Email address", Enabled: false, Scope: "email"},
		{ClaimName: "name", Description: "Full name", Enabled: false, Scope: "profile"},
	}
	return standards, nil
}

func (r *cpClaimsRepoMySQL) SetStandardClaimEnabled(ctx context.Context, claimName string, enabled bool) error {
	id := uuid.NewString()
	const q = `INSERT INTO cp_claims_config
		(id,tenant_id,claim_name,description,source_type,config,scopes,always_include,required,enabled,system,created_at,updated_at)
		VALUES (?,?,?,'','static','{}','[]',0,0,?,1,NOW(6),NOW(6))
		ON DUPLICATE KEY UPDATE enabled=VALUES(enabled),updated_at=NOW(6)`
	_, err := r.db.ExecContext(ctx, q, id, r.tenantID, claimName, enabled)
	return err
}

func (r *cpClaimsRepoMySQL) GetSettings(ctx context.Context) (*repository.ClaimsSettings, error) {
	s := &repository.ClaimsSettings{TenantID: r.tenantID}
	const q = `SELECT config,updated_at FROM cp_claims_config WHERE tenant_id=? AND claim_name='__settings__'`
	var configJSON []byte
	err := r.db.QueryRowContext(ctx, q, r.tenantID).Scan(&configJSON, &s.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(configJSON, s)
	s.TenantID = r.tenantID
	return s, nil
}

func (r *cpClaimsRepoMySQL) UpdateSettings(ctx context.Context, input repository.ClaimsSettingsInput) (*repository.ClaimsSettings, error) {
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
	configJSON, _ := json.Marshal(current)
	id := uuid.NewString()
	const q = `INSERT INTO cp_claims_config
		(id,tenant_id,claim_name,description,source_type,config,scopes,always_include,required,enabled,system,created_at,updated_at)
		VALUES (?,?,'__settings__','','static',?,'[]',0,0,1,1,NOW(6),NOW(6))
		ON DUPLICATE KEY UPDATE config=VALUES(config),updated_at=NOW(6)`
	_, err = r.db.ExecContext(ctx, q, id, r.tenantID, configJSON)
	if err != nil {
		return nil, err
	}
	return current, nil
}

func (r *cpClaimsRepoMySQL) GetEnabledClaimsForScopes(ctx context.Context, scopes []string) ([]repository.ClaimDefinition, error) {
	if len(scopes) == 0 {
		return nil, nil
	}
	// MySQL no tiene el operador && para arrays; usamos JSON_OVERLAPS (MySQL 8.0.17+)
	scopesJSON, _ := json.Marshal(scopes)
	const q = `SELECT id,tenant_id,claim_name,description,source_type,config,scopes,always_include,required,enabled,system,created_at,updated_at
	           FROM cp_claims_config
	           WHERE tenant_id=? AND enabled=1 AND claim_name != '__settings__'
	             AND (always_include=1 OR JSON_OVERLAPS(scopes, ?))`
	rows, err := r.db.QueryContext(ctx, q, r.tenantID, string(scopesJSON))
	if err != nil {
		return nil, fmt.Errorf("mysql_cp_claims: get enabled for scopes: %w", err)
	}
	defer rows.Close()
	var out []repository.ClaimDefinition
	for rows.Next() {
		cl, err := scanMySQLClaim(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *cl)
	}
	return out, rows.Err()
}

func scanMySQLClaim(row interface {
	Scan(dest ...any) error
}) (*repository.ClaimDefinition, error) {
	var cl repository.ClaimDefinition
	var configJSON, scopesJSON []byte
	err := row.Scan(
		&cl.ID, &cl.TenantID, &cl.Name, &cl.Description,
		&cl.Source, &configJSON, &scopesJSON,
		&cl.AlwaysInclude, &cl.Required, &cl.Enabled, &cl.System,
		&cl.CreatedAt, &cl.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(configJSON, &cl.ConfigData)
	_ = json.Unmarshal(scopesJSON, &cl.Scopes)
	return &cl, nil
}

func claimSourceTypeMySQL(source string) string {
	if source == "" {
		return "static"
	}
	return source
}

var _ repository.ClaimRepository = (*cpClaimsRepoMySQL)(nil)

// ═══════════════════════════════════════════════════════════════════════════════
// cpAdminRepoMySQL
// ═══════════════════════════════════════════════════════════════════════════════

type cpAdminRepoMySQL struct{ db *sql.DB }

const mysqlAdminCols = `id, email, name, role, tenant_ids, enabled, last_seen_at, disabled_at, created_at, updated_at`

func (r *cpAdminRepoMySQL) List(ctx context.Context, filter repository.AdminFilter) ([]repository.Admin, error) {
	q := `SELECT ` + mysqlAdminCols + ` FROM cp_admin WHERE 1=1`
	args := []any{}
	if filter.Disabled != nil {
		if *filter.Disabled {
			q += ` AND disabled_at IS NOT NULL`
		} else {
			q += ` AND disabled_at IS NULL`
		}
	}
	q += ` ORDER BY email`
	if filter.Limit > 0 {
		q += ` LIMIT ?`
		args = append(args, filter.Limit)
	}
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("mysql_cp_admin: list: %w", err)
	}
	defer rows.Close()
	var out []repository.Admin
	for rows.Next() {
		a, err := r.scanRow(rows)
		if err != nil {
			return nil, err
		}
		if filter.Type != nil && a.Type != *filter.Type {
			continue
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (r *cpAdminRepoMySQL) GetByID(ctx context.Context, id string) (*repository.Admin, error) {
	q := `SELECT ` + mysqlAdminCols + ` FROM cp_admin WHERE id=?`
	row := r.db.QueryRowContext(ctx, q, id)
	a, err := r.scanRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	return a, err
}

func (r *cpAdminRepoMySQL) GetByEmail(ctx context.Context, email string) (*repository.Admin, error) {
	q := `SELECT ` + mysqlAdminCols + ` FROM cp_admin WHERE email=?`
	row := r.db.QueryRowContext(ctx, q, email)
	a, err := r.scanRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	return a, err
}

func (r *cpAdminRepoMySQL) Create(ctx context.Context, input repository.CreateAdminInput) (*repository.Admin, error) {
	tenantSlugs := make([]string, len(input.TenantAccess))
	for i, e := range input.TenantAccess {
		tenantSlugs[i] = e.TenantID
	}
	tenantIDsJSON, _ := json.Marshal(tenantSlugs)
	adminType := string(input.Type)
	if adminType == "" {
		adminType = string(repository.AdminTypeGlobal)
	}
	id := uuid.NewString()
	const q = `INSERT INTO cp_admin (id,email,password_hash,name,role,tenant_ids,enabled,created_at,updated_at)
	           VALUES (?,?,?,?,?,?,1,NOW(6),NOW(6))`
	_, err := r.db.ExecContext(ctx, q, id, input.Email, input.PasswordHash, input.Name, adminType, tenantIDsJSON)
	if err != nil {
		if isMySQLDuplicate(err) {
			return nil, repository.ErrConflict
		}
		return nil, fmt.Errorf("mysql_cp_admin: create: %w", err)
	}
	return r.GetByID(ctx, id)
}

func (r *cpAdminRepoMySQL) Update(ctx context.Context, id string, input repository.UpdateAdminInput) (*repository.Admin, error) {
	setClauses := []string{}
	args := []any{}
	if input.Email != nil {
		setClauses = append(setClauses, "email=?")
		args = append(args, *input.Email)
	}
	if input.PasswordHash != nil {
		setClauses = append(setClauses, "password_hash=?")
		args = append(args, *input.PasswordHash)
	}
	if input.Name != nil {
		setClauses = append(setClauses, "name=?")
		args = append(args, *input.Name)
	}
	if input.TenantAccess != nil {
		slugs := make([]string, len(*input.TenantAccess))
		for i, e := range *input.TenantAccess {
			slugs[i] = e.TenantID
		}
		j, _ := json.Marshal(slugs)
		setClauses = append(setClauses, "tenant_ids=?")
		args = append(args, string(j))
	}
	if input.DisabledAt != nil {
		setClauses = append(setClauses, "disabled_at=?")
		args = append(args, *input.DisabledAt)
	}
	if len(setClauses) == 0 {
		return r.GetByID(ctx, id)
	}
	setClauses = append(setClauses, "updated_at=NOW(6)")
	args = append(args, id)
	q := `UPDATE cp_admin SET ` + strings.Join(setClauses, ",") + ` WHERE id=?`
	res, err := r.db.ExecContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("mysql_cp_admin: update: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, repository.ErrNotFound
	}
	return r.GetByID(ctx, id)
}

func (r *cpAdminRepoMySQL) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM cp_admin WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("mysql_cp_admin: delete: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *cpAdminRepoMySQL) CheckPassword(passwordHash, plainPassword string) bool {
	return password.Verify(plainPassword, passwordHash)
}

func (r *cpAdminRepoMySQL) UpdateLastSeen(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE cp_admin SET last_seen_at=NOW(6) WHERE id=?`, id)
	return err
}

func (r *cpAdminRepoMySQL) AssignTenants(ctx context.Context, adminID string, tenantIDs []string) error {
	j, _ := json.Marshal(tenantIDs)
	res, err := r.db.ExecContext(ctx, `UPDATE cp_admin SET tenant_ids=?,updated_at=NOW(6) WHERE id=?`, string(j), adminID)
	if err != nil {
		return fmt.Errorf("mysql_cp_admin: assign tenants: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *cpAdminRepoMySQL) HasAccessToTenant(ctx context.Context, adminID, tenantID string) (bool, error) {
	var role string
	err := r.db.QueryRowContext(ctx,
		`SELECT role FROM cp_admin WHERE id=? AND enabled=1 AND disabled_at IS NULL`,
		adminID,
	).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if role == string(repository.AdminTypeGlobal) {
		return true, nil
	}
	var dummy int
	err = r.db.QueryRowContext(ctx,
		`SELECT 1 FROM cp_admin WHERE id=? AND JSON_CONTAINS(tenant_ids,?) AND enabled=1 AND disabled_at IS NULL`,
		adminID, `"`+tenantID+`"`,
	).Scan(&dummy)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// SetInviteToken implementa AdminRepository.SetInviteToken
func (r *cpAdminRepoMySQL) SetInviteToken(ctx context.Context, id, tokenHash string, expiresAt time.Time) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE cp_admin SET invite_token_hash=?, invite_expires_at=?, status='pending', updated_at=NOW() WHERE id=?`,
		tokenHash, expiresAt, id)
	if err != nil {
		return fmt.Errorf("cp_admin_repo_mysql: set invite token: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrNotFound
	}
	return nil
}

// GetByInviteTokenHash implementa AdminRepository.GetByInviteTokenHash
func (r *cpAdminRepoMySQL) GetByInviteTokenHash(ctx context.Context, tokenHash string) (*repository.Admin, error) {
	const q = `SELECT id, email, name, role, tenant_ids, enabled, last_seen_at, disabled_at, created_at, updated_at FROM cp_admin WHERE invite_token_hash=? AND status='pending'`
	row := r.db.QueryRowContext(ctx, q, tokenHash)
	admin, err := r.scanRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cp_admin_repo_mysql: get by invite token: %w", err)
	}
	return admin, nil
}

// ActivateWithPassword implementa AdminRepository.ActivateWithPassword
func (r *cpAdminRepoMySQL) ActivateWithPassword(ctx context.Context, id, passwordHash string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE cp_admin SET password_hash=?, status='active', invite_token_hash=NULL, invite_expires_at=NULL, updated_at=NOW() WHERE id=?`,
		passwordHash, id)
	if err != nil {
		return fmt.Errorf("cp_admin_repo_mysql: activate with password: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *cpAdminRepoMySQL) scanRow(row interface {
	Scan(dest ...any) error
}) (*repository.Admin, error) {
	var a repository.Admin
	var role string
	var tenantIDsJSON []byte
	var enabled bool
	var lastSeenAt sql.NullTime
	var disabledAt sql.NullTime
	err := row.Scan(
		&a.ID, &a.Email, &a.Name, &role,
		&tenantIDsJSON, &enabled, &lastSeenAt, &disabledAt,
		&a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	a.Type = repository.AdminType(role)
	if lastSeenAt.Valid {
		a.LastSeenAt = &lastSeenAt.Time
	}
	if disabledAt.Valid {
		a.DisabledAt = &disabledAt.Time
	}
	var slugs []string
	_ = json.Unmarshal(tenantIDsJSON, &slugs)
	a.AssignedTenants = slugs
	a.TenantAccess = make([]repository.TenantAccessEntry, len(slugs))
	for i, s := range slugs {
		a.TenantAccess[i] = repository.TenantAccessEntry{TenantID: s, Role: "owner"}
	}
	return &a, nil
}

var _ repository.AdminRepository = (*cpAdminRepoMySQL)(nil)

func (r *cpAdminRepoMySQL) CreateEmailVerification(_ context.Context, _ repository.AdminEmailVerification) error {
	return fmt.Errorf("cpAdminRepoMySQL: CreateEmailVerification not supported")
}

func (r *cpAdminRepoMySQL) GetEmailVerificationByHash(_ context.Context, _ string) (*repository.AdminEmailVerification, error) {
	return nil, repository.ErrNotFound
}

func (r *cpAdminRepoMySQL) MarkEmailVerificationUsed(_ context.Context, _ string) error {
	return fmt.Errorf("cpAdminRepoMySQL: MarkEmailVerificationUsed not supported")
}

func (r *cpAdminRepoMySQL) UpdateEmailVerified(ctx context.Context, adminID string, verified bool) error {
	status := "active"
	if !verified {
		status = "pending_verification"
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE cp_admin SET email_verified=?, status=?, updated_at=NOW() WHERE id=?`,
		verified, status, adminID)
	return err
}

func (r *cpAdminRepoMySQL) UpdateSocialProvider(ctx context.Context, adminID, provider, plan string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE cp_admin SET social_provider=?, plan=?, updated_at=NOW() WHERE id=?`,
		provider, plan, adminID)
	return err
}

// UpdatePlan actualiza el campo plan del admin.
func (r *cpAdminRepoMySQL) UpdatePlan(ctx context.Context, adminID, plan string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE cp_admin SET plan=?, updated_at=NOW() WHERE id=?`,
		plan, adminID)
	return err
}

// CountTenantsByAdmin stub: retorna 0 (fail-open).
func (r *cpAdminRepoMySQL) CountTenantsByAdmin(_ context.Context, _ string) (int, error) {
	return 0, nil
}

// CountAdminsByOwner cuenta los admins creados por el admin dado.
func (r *cpAdminRepoMySQL) CountAdminsByOwner(ctx context.Context, adminID string) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cp_admin WHERE created_by=?`, adminID).Scan(&count)
	if err != nil {
		return 0, nil // fail-open
	}
	return count, nil
}

// GetCurrentMAU stub: retorna 0 (fail-open).
func (r *cpAdminRepoMySQL) GetCurrentMAU(_ context.Context, _ string) (int, error) {
	return 0, nil
}

// SetOnboardingCompleted stub: retorna nil (MySQL no soporta onboarding_completed aún).
func (r *cpAdminRepoMySQL) SetOnboardingCompleted(_ context.Context, _ string, _ bool) error {
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// cpAdminRefreshTokenRepoMySQL
// ═══════════════════════════════════════════════════════════════════════════════

type cpAdminRefreshTokenRepoMySQL struct{ db *sql.DB }

func (r *cpAdminRefreshTokenRepoMySQL) GetByTokenHash(ctx context.Context, tokenHash string) (*repository.AdminRefreshToken, error) {
	const q = `SELECT token_hash,admin_id,expires_at,created_at FROM cp_admin_refresh_token WHERE token_hash=?`
	var t repository.AdminRefreshToken
	err := r.db.QueryRowContext(ctx, q, tokenHash).Scan(&t.TokenHash, &t.AdminID, &t.ExpiresAt, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	return &t, err
}

func (r *cpAdminRefreshTokenRepoMySQL) ListByAdminID(ctx context.Context, adminID string) ([]repository.AdminRefreshToken, error) {
	const q = `SELECT token_hash,admin_id,expires_at,created_at FROM cp_admin_refresh_token WHERE admin_id=?`
	rows, err := r.db.QueryContext(ctx, q, adminID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []repository.AdminRefreshToken
	for rows.Next() {
		var t repository.AdminRefreshToken
		if err := rows.Scan(&t.TokenHash, &t.AdminID, &t.ExpiresAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r *cpAdminRefreshTokenRepoMySQL) Create(ctx context.Context, input repository.CreateAdminRefreshTokenInput) error {
	const q = `INSERT INTO cp_admin_refresh_token (admin_id,token_hash,expires_at,created_at) VALUES (?,?,?,NOW(6))`
	_, err := r.db.ExecContext(ctx, q, input.AdminID, input.TokenHash, input.ExpiresAt)
	if err != nil {
		if isMySQLDuplicate(err) {
			return repository.ErrConflict
		}
		return err
	}
	return nil
}

func (r *cpAdminRefreshTokenRepoMySQL) Delete(ctx context.Context, tokenHash string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM cp_admin_refresh_token WHERE token_hash=?`, tokenHash)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *cpAdminRefreshTokenRepoMySQL) DeleteByAdminID(ctx context.Context, adminID string) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM cp_admin_refresh_token WHERE admin_id=?`, adminID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (r *cpAdminRefreshTokenRepoMySQL) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM cp_admin_refresh_token WHERE expires_at<?`, now)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

var _ repository.AdminRefreshTokenRepository = (*cpAdminRefreshTokenRepoMySQL)(nil)

// ─── Helper: Detectar error de FK/duplicate en MySQL ───

func isMySQLDuplicate(err error) bool {
	return err != nil && strings.Contains(err.Error(), "Duplicate entry")
}
