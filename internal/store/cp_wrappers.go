package store

import (
	"context"
	"fmt"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// ─── Interfaces exportadas: repos FS internos (con tenantSlug) ───────────────
// Estas interfaces replican las firmas del FS adapter (con tenantSlug) y son
// exportadas para que el FS adapter (package fs) pueda declarar conformidad.
// Son usadas internamente por los wrappers; los callers externos no las usan.

// FSInternalClientRepo expone los métodos del clientRepo del FS adapter.
// Retiene el parámetro tenantSlug que el adapter requiere internamente.
type FSInternalClientRepo interface {
	Get(ctx context.Context, tenantSlug, clientID string) (*repository.Client, error)
	GetByUUID(ctx context.Context, uuid string) (*repository.Client, *repository.ClientVersion, error)
	List(ctx context.Context, tenantSlug, query string) ([]repository.Client, error)
	Create(ctx context.Context, tenantSlug string, input repository.ClientInput) (*repository.Client, error)
	Update(ctx context.Context, tenantSlug string, input repository.ClientInput) (*repository.Client, error)
	Delete(ctx context.Context, tenantSlug, clientID string) error
	DecryptSecret(ctx context.Context, tenantSlug, clientID string) (string, error)
	ValidateClientID(id string) bool
	ValidateRedirectURI(uri string) bool
	IsScopeAllowed(client *repository.Client, scope string) bool
}

// FSInternalScopeRepo expone los métodos del scopeRepo del FS adapter.
type FSInternalScopeRepo interface {
	Create(ctx context.Context, tenantSlug string, input repository.ScopeInput) (*repository.Scope, error)
	GetByName(ctx context.Context, tenantSlug, name string) (*repository.Scope, error)
	List(ctx context.Context, tenantSlug string) ([]repository.Scope, error)
	Update(ctx context.Context, tenantSlug string, input repository.ScopeInput) (*repository.Scope, error)
	Delete(ctx context.Context, tenantSlug, scopeID string) error
	Upsert(ctx context.Context, tenantSlug string, input repository.ScopeInput) (*repository.Scope, error)
}

// FSInternalClaimRepo expone los métodos del claimRepo del FS adapter.
type FSInternalClaimRepo interface {
	Create(ctx context.Context, tenantSlug string, input repository.ClaimInput) (*repository.ClaimDefinition, error)
	Get(ctx context.Context, tenantSlug, claimID string) (*repository.ClaimDefinition, error)
	GetByName(ctx context.Context, tenantSlug, name string) (*repository.ClaimDefinition, error)
	List(ctx context.Context, tenantSlug string) ([]repository.ClaimDefinition, error)
	Update(ctx context.Context, tenantSlug, claimID string, input repository.ClaimInput) (*repository.ClaimDefinition, error)
	Delete(ctx context.Context, tenantSlug, claimID string) error
	GetStandardClaimsConfig(ctx context.Context, tenantSlug string) ([]repository.StandardClaimConfig, error)
	SetStandardClaimEnabled(ctx context.Context, tenantSlug, claimName string, enabled bool) error
	GetSettings(ctx context.Context, tenantSlug string) (*repository.ClaimsSettings, error)
	UpdateSettings(ctx context.Context, tenantSlug string, input repository.ClaimsSettingsInput) (*repository.ClaimsSettings, error)
	GetEnabledClaimsForScopes(ctx context.Context, tenantSlug string, scopes []string) ([]repository.ClaimDefinition, error)
}

// FSRawConnection es una interfaz optativa que el FS adapter satisface.
// Permite que factory.go acceda a los repos internos (con tenantSlug) para
// construir los wrappers tenant-scoped sin type-assertions inseguros.
type FSRawConnection interface {
	RawClients() FSInternalClientRepo
	RawScopes() FSInternalScopeRepo
	RawClaims() FSInternalClaimRepo
}

// mustFSRaw hace type assertion a FSRawConnection y entra en pánico si falla.
// Solo debe llamarse con la fsConn (adapter FS) que siempre satisface esta interfaz.
func mustFSRaw(conn interface{ Name() string }) FSRawConnection {
	raw, ok := conn.(FSRawConnection)
	if !ok {
		panic(fmt.Sprintf("store: adapter %q does not implement FSRawConnection; only the FS adapter supports Control Plane repos", conn.Name()))
	}
	return raw
}

// ─── Wrappers con tenant pre-bound ───────────────────────────────────────────
// Cada wrapper almacena el slug en construcción y lo inyecta en cada llamada
// al delegate (FS adapter). Satisface la nueva interfaz pública (sin tenantSlug).

// tenantScopedClientRepo pre-bindea el slug y delega al FS clientRepo.
type tenantScopedClientRepo struct {
	delegate   FSInternalClientRepo
	tenantSlug string
}

func (r *tenantScopedClientRepo) Get(ctx context.Context, clientID string) (*repository.Client, error) {
	return r.delegate.Get(ctx, r.tenantSlug, clientID)
}
func (r *tenantScopedClientRepo) GetByUUID(ctx context.Context, uuid string) (*repository.Client, *repository.ClientVersion, error) {
	return r.delegate.GetByUUID(ctx, uuid)
}
func (r *tenantScopedClientRepo) List(ctx context.Context, query string) ([]repository.Client, error) {
	return r.delegate.List(ctx, r.tenantSlug, query)
}
func (r *tenantScopedClientRepo) Create(ctx context.Context, input repository.ClientInput) (*repository.Client, error) {
	return r.delegate.Create(ctx, r.tenantSlug, input)
}
func (r *tenantScopedClientRepo) Update(ctx context.Context, input repository.ClientInput) (*repository.Client, error) {
	return r.delegate.Update(ctx, r.tenantSlug, input)
}
func (r *tenantScopedClientRepo) Delete(ctx context.Context, clientID string) error {
	return r.delegate.Delete(ctx, r.tenantSlug, clientID)
}
func (r *tenantScopedClientRepo) DecryptSecret(ctx context.Context, clientID string) (string, error) {
	return r.delegate.DecryptSecret(ctx, r.tenantSlug, clientID)
}
func (r *tenantScopedClientRepo) ValidateClientID(id string) bool {
	return r.delegate.ValidateClientID(id)
}
func (r *tenantScopedClientRepo) ValidateRedirectURI(uri string) bool {
	return r.delegate.ValidateRedirectURI(uri)
}
func (r *tenantScopedClientRepo) IsScopeAllowed(client *repository.Client, scope string) bool {
	return r.delegate.IsScopeAllowed(client, scope)
}

// tenantScopedScopeRepo pre-bindea el slug y delega al FS scopeRepo.
type tenantScopedScopeRepo struct {
	delegate   FSInternalScopeRepo
	tenantSlug string
}

func (r *tenantScopedScopeRepo) Create(ctx context.Context, input repository.ScopeInput) (*repository.Scope, error) {
	return r.delegate.Create(ctx, r.tenantSlug, input)
}
func (r *tenantScopedScopeRepo) GetByName(ctx context.Context, name string) (*repository.Scope, error) {
	return r.delegate.GetByName(ctx, r.tenantSlug, name)
}
func (r *tenantScopedScopeRepo) List(ctx context.Context) ([]repository.Scope, error) {
	return r.delegate.List(ctx, r.tenantSlug)
}
func (r *tenantScopedScopeRepo) Update(ctx context.Context, input repository.ScopeInput) (*repository.Scope, error) {
	return r.delegate.Update(ctx, r.tenantSlug, input)
}
func (r *tenantScopedScopeRepo) Delete(ctx context.Context, scopeID string) error {
	return r.delegate.Delete(ctx, r.tenantSlug, scopeID)
}
func (r *tenantScopedScopeRepo) Upsert(ctx context.Context, input repository.ScopeInput) (*repository.Scope, error) {
	return r.delegate.Upsert(ctx, r.tenantSlug, input)
}

// tenantScopedClaimRepo pre-bindea el slug y delega al FS claimRepo.
type tenantScopedClaimRepo struct {
	delegate   FSInternalClaimRepo
	tenantSlug string
}

func (r *tenantScopedClaimRepo) Create(ctx context.Context, input repository.ClaimInput) (*repository.ClaimDefinition, error) {
	return r.delegate.Create(ctx, r.tenantSlug, input)
}
func (r *tenantScopedClaimRepo) Get(ctx context.Context, claimID string) (*repository.ClaimDefinition, error) {
	return r.delegate.Get(ctx, r.tenantSlug, claimID)
}
func (r *tenantScopedClaimRepo) GetByName(ctx context.Context, name string) (*repository.ClaimDefinition, error) {
	return r.delegate.GetByName(ctx, r.tenantSlug, name)
}
func (r *tenantScopedClaimRepo) List(ctx context.Context) ([]repository.ClaimDefinition, error) {
	return r.delegate.List(ctx, r.tenantSlug)
}
func (r *tenantScopedClaimRepo) Update(ctx context.Context, claimID string, input repository.ClaimInput) (*repository.ClaimDefinition, error) {
	return r.delegate.Update(ctx, r.tenantSlug, claimID, input)
}
func (r *tenantScopedClaimRepo) Delete(ctx context.Context, claimID string) error {
	return r.delegate.Delete(ctx, r.tenantSlug, claimID)
}
func (r *tenantScopedClaimRepo) GetStandardClaimsConfig(ctx context.Context) ([]repository.StandardClaimConfig, error) {
	return r.delegate.GetStandardClaimsConfig(ctx, r.tenantSlug)
}
func (r *tenantScopedClaimRepo) SetStandardClaimEnabled(ctx context.Context, claimName string, enabled bool) error {
	return r.delegate.SetStandardClaimEnabled(ctx, r.tenantSlug, claimName, enabled)
}
func (r *tenantScopedClaimRepo) GetSettings(ctx context.Context) (*repository.ClaimsSettings, error) {
	return r.delegate.GetSettings(ctx, r.tenantSlug)
}
func (r *tenantScopedClaimRepo) UpdateSettings(ctx context.Context, input repository.ClaimsSettingsInput) (*repository.ClaimsSettings, error) {
	return r.delegate.UpdateSettings(ctx, r.tenantSlug, input)
}
func (r *tenantScopedClaimRepo) GetEnabledClaimsForScopes(ctx context.Context, scopes []string) ([]repository.ClaimDefinition, error) {
	return r.delegate.GetEnabledClaimsForScopes(ctx, r.tenantSlug, scopes)
}

// ─── Compile-time interface checks ───────────────────────────────────────────

var _ repository.ClientRepository = (*tenantScopedClientRepo)(nil)
var _ repository.ScopeRepository = (*tenantScopedScopeRepo)(nil)
var _ repository.ClaimRepository = (*tenantScopedClaimRepo)(nil)
