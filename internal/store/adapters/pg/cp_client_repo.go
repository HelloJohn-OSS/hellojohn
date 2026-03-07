// internal/store/adapters/pg/cp_client_repo.go
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/security/secretbox"
)

// cpClientRepo implementa repository.ClientRepository sobre cp_client.
// tenantID (UUID de cp_tenant) se inyecta al construir el repo.
type cpClientRepo struct {
	pool     *pgxpool.Pool
	tenantID string
}

// ─── Columnas de SELECT para todas las queries ───

const cpClientColumns = `
	id, tenant_id, client_id, name, type, secret_enc,
	settings, redirect_uris, allowed_scopes, enabled, created_at, updated_at`

func (r *cpClientRepo) Get(ctx context.Context, clientID string) (*repository.Client, error) {
	q := `SELECT` + cpClientColumns + `FROM cp_client WHERE tenant_id=$1 AND client_id=$2`
	row := r.pool.QueryRow(ctx, q, r.tenantID, clientID)
	c, err := scanClient(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cp_client_repo: get: %w", err)
	}
	return c, nil
}

func (r *cpClientRepo) GetByUUID(ctx context.Context, id string) (*repository.Client, *repository.ClientVersion, error) {
	q := `SELECT` + cpClientColumns + `FROM cp_client WHERE id=$1`
	row := r.pool.QueryRow(ctx, q, id)
	c, err := scanClient(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("cp_client_repo: get by uuid: %w", err)
	}
	return c, nil, nil
}

func (r *cpClientRepo) List(ctx context.Context, query string) ([]repository.Client, error) {
	var (
		pgRows interface {
			Next() bool
			Scan(dest ...any) error
			Close()
			Err() error
		}
		err error
	)
	if query != "" {
		q := `SELECT` + cpClientColumns + `
			  FROM cp_client
			  WHERE tenant_id=$1 AND (name ILIKE '%'||$2||'%' OR client_id ILIKE '%'||$2||'%')
			  ORDER BY name`
		pgRows, err = r.pool.Query(ctx, q, r.tenantID, query)
	} else {
		q := `SELECT` + cpClientColumns + `FROM cp_client WHERE tenant_id=$1 ORDER BY name`
		pgRows, err = r.pool.Query(ctx, q, r.tenantID)
	}
	if err != nil {
		return nil, fmt.Errorf("cp_client_repo: list: %w", err)
	}
	defer pgRows.Close()

	var out []repository.Client
	for pgRows.Next() {
		c, err := scanClient(pgRows)
		if err != nil {
			return nil, fmt.Errorf("cp_client_repo: scan: %w", err)
		}
		out = append(out, *c)
	}
	return out, pgRows.Err()
}

func (r *cpClientRepo) Create(ctx context.Context, input repository.ClientInput) (*repository.Client, error) {
	settingsJSON, err := json.Marshal(buildClientSettings(input))
	if err != nil {
		return nil, fmt.Errorf("cp_client_repo: marshal settings: %w", err)
	}
	redirectURIs := nullableSlice(input.RedirectURIs)
	scopes := nullableSlice(input.Scopes)
	var secretEnc *string
	if input.Secret != "" {
		secretEnc = &input.Secret
	}
	q := `INSERT INTO cp_client
			(tenant_id, client_id, name, type, secret_enc, settings, redirect_uris, allowed_scopes, enabled, created_at, updated_at)
		  VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true,now(),now())
		  ON CONFLICT (tenant_id,client_id) DO UPDATE
		    SET name=$3, type=$4, secret_enc=COALESCE($5,cp_client.secret_enc),
		        settings=$6, redirect_uris=$7, allowed_scopes=$8, updated_at=now()
		  RETURNING` + cpClientColumns
	row := r.pool.QueryRow(ctx, q,
		r.tenantID, input.ClientID, input.Name, input.Type,
		secretEnc, settingsJSON, redirectURIs, scopes)
	c, err := scanClient(row)
	if err != nil {
		if isPgUniqueViolation(err) {
			return nil, repository.ErrConflict
		}
		return nil, fmt.Errorf("cp_client_repo: create: %w", err)
	}
	return c, nil
}

func (r *cpClientRepo) Update(ctx context.Context, input repository.ClientInput) (*repository.Client, error) {
	settingsJSON, err := json.Marshal(buildClientSettings(input))
	if err != nil {
		return nil, fmt.Errorf("cp_client_repo: marshal settings: %w", err)
	}
	redirectURIs := nullableSlice(input.RedirectURIs)
	scopes := nullableSlice(input.Scopes)
	var secretEnc *string
	if input.Secret != "" {
		secretEnc = &input.Secret
	}
	q := `UPDATE cp_client
		  SET name=$3,type=$4,secret_enc=COALESCE($5,secret_enc),
		      settings=$6,redirect_uris=$7,allowed_scopes=$8,updated_at=now()
		  WHERE tenant_id=$1 AND client_id=$2
		  RETURNING` + cpClientColumns
	row := r.pool.QueryRow(ctx, q,
		r.tenantID, input.ClientID, input.Name, input.Type,
		secretEnc, settingsJSON, redirectURIs, scopes)
	c, err := scanClient(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cp_client_repo: update: %w", err)
	}
	return c, nil
}

func (r *cpClientRepo) Delete(ctx context.Context, clientID string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM cp_client WHERE tenant_id=$1 AND client_id=$2`, r.tenantID, clientID)
	if err != nil {
		return fmt.Errorf("cp_client_repo: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *cpClientRepo) DecryptSecret(ctx context.Context, clientID string) (string, error) {
	var enc *string
	err := r.pool.QueryRow(ctx,
		`SELECT secret_enc FROM cp_client WHERE tenant_id=$1 AND client_id=$2`,
		r.tenantID, clientID,
	).Scan(&enc)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", repository.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("cp_client_repo: decrypt secret: %w", err)
	}
	if enc == nil || *enc == "" {
		return "", nil
	}
	return secretbox.Decrypt(*enc)
}

// ─── Validaciones puras (copiadas del FS adapter) ───

func (r *cpClientRepo) ValidateClientID(id string) bool {
	return len(id) >= 3 && len(id) <= 64
}

func (r *cpClientRepo) ValidateRedirectURI(uri string) bool {
	uri = strings.ToLower(strings.TrimSpace(uri))
	return strings.HasPrefix(uri, "https://") ||
		strings.HasPrefix(uri, "http://localhost") ||
		strings.HasPrefix(uri, "http://127.0.0.1")
}

func (r *cpClientRepo) IsScopeAllowed(client *repository.Client, scope string) bool {
	for _, s := range client.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// ─── Scan helpers ───

// scanClient lee una fila de cp_client en *repository.Client.
// Columnas en orden: id(PK), tenant_id, client_id, name, type, secret_enc,
//
//	settings, redirect_uris, allowed_scopes, enabled, created_at, updated_at
func scanClient(row interface {
	Scan(dest ...any) error
}) (*repository.Client, error) {
	var (
		pkID          string // UUID interno de cp_client.id
		c             repository.Client
		secretEnc     *string
		settingsJSON  []byte
		redirectURIs  []string
		allowedScopes []string
		enabled       bool
		createdAt     interface{}
		updatedAt     interface{}
	)
	err := row.Scan(
		&pkID, &c.TenantID, &c.ClientID, &c.Name, &c.Type, &secretEnc,
		&settingsJSON, &redirectURIs, &allowedScopes,
		&enabled, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}
	c.ID = pkID
	c.RedirectURIs = redirectURIs
	c.Scopes = allowedScopes
	if secretEnc != nil {
		c.SecretEnc = *secretEnc
	}
	if len(settingsJSON) > 0 {
		applyClientSettings(&c, settingsJSON)
	}
	return &c, nil
}

// buildClientSettings convierte los campos "extra" de ClientInput a JSON para la columna settings.
func buildClientSettings(input repository.ClientInput) map[string]any {
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

// applyClientSettings deserializa la columna settings de vuelta en el Client.
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

// nullableSlice convierte nil a un slice vacío para evitar NULL en DB.
func nullableSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// NewClientRepo expone el repo con tenantID pre-inyectado (para Factory y sync tool).
func (c *pgConnection) NewClientRepo(tenantID string) repository.ClientRepository {
	return &cpClientRepo{pool: c.pool, tenantID: tenantID}
}

// Verificación en compilación.
var _ repository.ClientRepository = (*cpClientRepo)(nil)
