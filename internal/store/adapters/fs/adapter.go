// Package fs implementa el adapter FileSystem para store/v2.
// Lee archivos YAML directamente, sin dependencias de controlplane/fs.
package fs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

func init() {
	store.RegisterAdapter(&fsAdapter{})
}

// fsAdapter implementa store.Adapter para FileSystem.
type fsAdapter struct{}

func (a *fsAdapter) Name() string { return "fs" }

func (a *fsAdapter) Connect(ctx context.Context, cfg store.AdapterConfig) (store.AdapterConnection, error) {
	root := cfg.FSRoot
	if root == "" {
		root = "data"
	}

	// Verificar que existe, si no existe lo creamos automáticamente
	info, err := os.Stat(root)
	if err != nil {
		if os.IsNotExist(err) {
			// Crear el directorio raíz automáticamente
			if mkErr := os.MkdirAll(root, 0755); mkErr != nil {
				return nil, fmt.Errorf("fs: failed to create root path %s: %w", root, mkErr)
			}
		} else {
			return nil, fmt.Errorf("fs: root path error: %w", err)
		}
	} else if !info.IsDir() {
		return nil, fmt.Errorf("fs: root path is not a directory: %s", root)
	}

	return &fsConnection{
		root:             root,
		signingMasterKey: cfg.SigningMasterKey,
	}, nil
}

// fsConnection representa una conexión activa al FileSystem.
type fsConnection struct {
	root             string
	mu               sync.RWMutex
	signingMasterKey string // hex, 64 chars - inyectado al iniciar
}

func (c *fsConnection) Name() string { return "fs" }

func (c *fsConnection) Ping(ctx context.Context) error {
	_, err := os.Stat(c.root)
	return err
}

func (c *fsConnection) Close() error { return nil }

// ─── Repositorios soportados ───

func (c *fsConnection) Tenants() repository.TenantRepository { return &tenantRepo{conn: c} }
func (c *fsConnection) Keys() repository.KeyRepository {
	return newKeyRepo(filepath.Join(c.root, "keys"), c.signingMasterKey)
}
func (c *fsConnection) Admins() repository.AdminRepository { return newAdminRepo(c.root) }
func (c *fsConnection) AdminRefreshTokens() repository.AdminRefreshTokenRepository {
	return newAdminRefreshTokenRepo(c.root)
}
func (c *fsConnection) APIKeys() repository.APIKeyRepository       { return newAPIKeyRepo(c.root) }
func (c *fsConnection) CloudUsers() repository.CloudUserRepository             { return nil }
func (c *fsConnection) CloudInstances() repository.CloudInstanceRepository     { return nil }

// ─── FSRawConnection (store-internal) ───
// Estos métodos satisfacen la interfaz store.FSRawConnection y permiten que
// factory.go acceda a los repos internos del FS adapter (con tenantSlug)
// para construir los wrappers tenant-scoped.

func (c *fsConnection) RawClients() store.FSInternalClientRepo { return &clientRepo{conn: c} }
func (c *fsConnection) RawScopes() store.FSInternalScopeRepo   { return &scopeRepo{conn: c} }
func (c *fsConnection) RawClaims() store.FSInternalClaimRepo   { return &claimRepo{conn: c} }

// Data plane (NO soportado por FS)
func (c *fsConnection) Users() repository.UserRepository             { return nil }
func (c *fsConnection) Tokens() repository.TokenRepository           { return nil }
func (c *fsConnection) MFA() repository.MFARepository                { return nil }
func (c *fsConnection) Consents() repository.ConsentRepository       { return nil }
func (c *fsConnection) RBAC() repository.RBACRepository              { return nil }
func (c *fsConnection) Schema() repository.SchemaRepository          { return nil }
func (c *fsConnection) EmailTokens() repository.EmailTokenRepository { return nil }
func (c *fsConnection) Identities() repository.IdentityRepository    { return nil }
func (c *fsConnection) Sessions() repository.SessionRepository       { return nil }
func (c *fsConnection) Audit() repository.AuditRepository            { return nil }
func (c *fsConnection) Webhooks() repository.WebhookRepository       { return nil }
func (c *fsConnection) Invitations() repository.InvitationRepository { return nil }
func (c *fsConnection) WebAuthn() repository.WebAuthnRepository      { return nil }

// ─── Helpers ───

func (c *fsConnection) tenantPath(slug string) string {
	return filepath.Join(c.root, "tenants", slug)
}

func (c *fsConnection) tenantFile(slug string) string {
	return filepath.Join(c.tenantPath(slug), "tenant.yaml")
}

func (c *fsConnection) clientsFile(slug string) string {
	return filepath.Join(c.tenantPath(slug), "clients.yaml")
}

func (c *fsConnection) scopesFile(slug string) string {
	return filepath.Join(c.tenantPath(slug), "scopes.yaml")
}

// ─── TenantRepository ───

type tenantRepo struct{ conn *fsConnection }

func (r *tenantRepo) List(ctx context.Context) ([]repository.Tenant, error) {
	tenantsDir := filepath.Join(r.conn.root, "tenants")
	entries, err := os.ReadDir(tenantsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []repository.Tenant{}, nil
		}
		return nil, fmt.Errorf("fs: read tenants dir: %w", err)
	}

	var tenants []repository.Tenant
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		slug := entry.Name()
		if strings.HasPrefix(slug, ".") {
			continue // Ignorar ocultos
		}
		tenant, err := r.GetBySlug(ctx, slug)
		if err != nil {
			continue // Ignorar tenants inválidos
		}
		tenants = append(tenants, *tenant)
	}
	return tenants, nil
}

func (r *tenantRepo) GetBySlug(ctx context.Context, slug string) (*repository.Tenant, error) {
	r.conn.mu.RLock()
	defer r.conn.mu.RUnlock()

	data, err := os.ReadFile(r.conn.tenantFile(slug))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, repository.ErrNotFound
		}
		return nil, fmt.Errorf("fs: read tenant file: %w", err)
	}

	var raw tenantYAML
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("fs: parse tenant yaml: %w", err)
	}

	return raw.toRepository(slug), nil
}

func (r *tenantRepo) GetByID(ctx context.Context, id string) (*repository.Tenant, error) {
	// Buscar en todos los tenants
	tenants, err := r.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, t := range tenants {
		if t.ID == id {
			return &t, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (r *tenantRepo) Create(ctx context.Context, tenant *repository.Tenant) error {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	// Verificar que no existe
	tenantPath := r.conn.tenantPath(tenant.Slug)
	if _, err := os.Stat(tenantPath); err == nil {
		return repository.ErrConflict
	}

	// Crear directorio
	if err := os.MkdirAll(tenantPath, 0755); err != nil {
		return fmt.Errorf("fs: create tenant dir: %w", err)
	}

	// Escribir tenant.yaml
	raw := toTenantYAML(tenant)
	data, err := yaml.Marshal(raw)
	if err != nil {
		return fmt.Errorf("fs: marshal tenant: %w", err)
	}

	return os.WriteFile(r.conn.tenantFile(tenant.Slug), data, 0600)
}

func (r *tenantRepo) Update(ctx context.Context, tenant *repository.Tenant) error {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	// Verificar que existe
	if _, err := os.Stat(r.conn.tenantFile(tenant.Slug)); os.IsNotExist(err) {
		return repository.ErrNotFound
	}

	raw := toTenantYAML(tenant)
	data, err := yaml.Marshal(raw)
	if err != nil {
		return fmt.Errorf("fs: marshal tenant: %w", err)
	}

	return os.WriteFile(r.conn.tenantFile(tenant.Slug), data, 0600)
}

func (r *tenantRepo) Delete(ctx context.Context, slug string) error {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	tenantPath := r.conn.tenantPath(slug)
	if _, err := os.Stat(tenantPath); os.IsNotExist(err) {
		return repository.ErrNotFound
	}

	return os.RemoveAll(tenantPath)
}

func (r *tenantRepo) UpdateSettings(ctx context.Context, slug string, settings *repository.TenantSettings) error {
	// Acquire write lock for the entire read-modify-write to prevent lost-update races.
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	data, err := os.ReadFile(r.conn.tenantFile(slug))
	if err != nil {
		if os.IsNotExist(err) {
			return repository.ErrNotFound
		}
		return fmt.Errorf("fs: UpdateSettings read: %w", err)
	}
	var raw tenantYAML
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("fs: UpdateSettings unmarshal: %w", err)
	}

	tenant := raw.toRepository(slug)
	tenant.Settings = *settings

	marshalData, err := yaml.Marshal(toTenantYAML(tenant))
	if err != nil {
		return fmt.Errorf("fs: UpdateSettings marshal: %w", err)
	}
	return os.WriteFile(r.conn.tenantFile(slug), marshalData, 0600)
}

// ─── ClientRepository ───

type clientRepo struct{ conn *fsConnection }

func (r *clientRepo) Get(ctx context.Context, tenantSlug, clientID string) (*repository.Client, error) {
	clients, err := r.List(ctx, tenantSlug, "")
	if err != nil {
		return nil, err
	}
	for _, c := range clients {
		if c.ClientID == clientID {
			return &c, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (r *clientRepo) GetByUUID(ctx context.Context, uuid string) (*repository.Client, *repository.ClientVersion, error) {
	return nil, nil, repository.ErrNotImplemented
}

func (r *clientRepo) List(ctx context.Context, tenantSlug string, query string) ([]repository.Client, error) {
	r.conn.mu.RLock()
	defer r.conn.mu.RUnlock()

	data, err := os.ReadFile(r.conn.clientsFile(tenantSlug))
	if err != nil {
		if os.IsNotExist(err) {
			return []repository.Client{}, nil
		}
		return nil, fmt.Errorf("fs: read clients file: %w", err)
	}

	var raw clientsYAML
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("fs: parse clients yaml: %w", err)
	}

	var clients []repository.Client
	for _, c := range raw.Clients {
		client := c.toRepository(tenantSlug)
		if query == "" || strings.Contains(strings.ToLower(client.Name), strings.ToLower(query)) {
			clients = append(clients, *client)
		}
	}
	return clients, nil
}

func (r *clientRepo) Create(ctx context.Context, tenantSlug string, input repository.ClientInput) (*repository.Client, error) {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	// Leer existentes
	clients, err := r.listRaw(tenantSlug)
	if err != nil {
		return nil, err
	}

	// Verificar que no existe
	for _, c := range clients {
		if c.ClientID == input.ClientID {
			return nil, repository.ErrConflict
		}
	}

	// Agregar nuevo
	newClient := clientYAML{
		ClientID:                 input.ClientID,
		Name:                     input.Name,
		Type:                     input.Type,
		AuthProfile:              input.AuthProfile,
		RedirectURIs:             input.RedirectURIs,
		AllowedOrigins:           input.AllowedOrigins,
		Providers:                input.Providers,
		Scopes:                   input.Scopes,
		SecretEnc:                input.Secret,
		RequireEmailVerification: input.RequireEmailVerification,
		ResetPasswordURL:         input.ResetPasswordURL,
		VerifyEmailURL:           input.VerifyEmailURL,
		ClaimSchema:              input.ClaimSchema,
		ClaimMapping:             input.ClaimMapping,
		GrantTypes:               input.GrantTypes,
		AccessTokenTTL:           input.AccessTokenTTL,
		RefreshTokenTTL:          input.RefreshTokenTTL,
		IDTokenTTL:               input.IDTokenTTL,
		PostLogoutURIs:           input.PostLogoutURIs,
		Description:              input.Description,
	}
	clients = append(clients, newClient)

	// Escribir
	if err := r.writeClients(tenantSlug, clients); err != nil {
		return nil, err
	}

	return newClient.toRepository(tenantSlug), nil
}

func (r *clientRepo) Update(ctx context.Context, tenantSlug string, input repository.ClientInput) (*repository.Client, error) {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	clients, err := r.listRaw(tenantSlug)
	if err != nil {
		return nil, err
	}

	found := false
	for i, c := range clients {
		if c.ClientID == input.ClientID {
			secretEnc := input.Secret
			if strings.TrimSpace(secretEnc) == "" {
				secretEnc = c.SecretEnc
			}

			clients[i] = clientYAML{
				ClientID:                 input.ClientID,
				Name:                     input.Name,
				Type:                     input.Type,
				AuthProfile:              input.AuthProfile,
				RedirectURIs:             input.RedirectURIs,
				AllowedOrigins:           input.AllowedOrigins,
				Providers:                input.Providers,
				Scopes:                   input.Scopes,
				SecretEnc:                secretEnc,
				RequireEmailVerification: input.RequireEmailVerification,
				ResetPasswordURL:         input.ResetPasswordURL,
				VerifyEmailURL:           input.VerifyEmailURL,
				ClaimSchema:              input.ClaimSchema,
				ClaimMapping:             input.ClaimMapping,
				GrantTypes:               input.GrantTypes,
				AccessTokenTTL:           input.AccessTokenTTL,
				RefreshTokenTTL:          input.RefreshTokenTTL,
				IDTokenTTL:               input.IDTokenTTL,
				PostLogoutURIs:           input.PostLogoutURIs,
				Description:              input.Description,
			}
			found = true
			break
		}
	}

	if !found {
		return nil, repository.ErrNotFound
	}

	if err := r.writeClients(tenantSlug, clients); err != nil {
		return nil, err
	}

	// Return the updated client directly from the already-loaded slice
	// (cannot call r.Get here — it would try to acquire conn.mu.RLock while we hold conn.mu.Lock → deadlock)
	for _, c := range clients {
		if c.ClientID == input.ClientID {
			return c.toRepository(tenantSlug), nil
		}
	}
	return nil, repository.ErrNotFound
}

func (r *clientRepo) Delete(ctx context.Context, tenantSlug, clientID string) error {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	clients, err := r.listRaw(tenantSlug)
	if err != nil {
		return err
	}

	var filtered []clientYAML
	found := false
	for _, c := range clients {
		if c.ClientID == clientID {
			found = true
			continue
		}
		filtered = append(filtered, c)
	}

	if !found {
		return repository.ErrNotFound
	}

	return r.writeClients(tenantSlug, filtered)
}

func (r *clientRepo) DecryptSecret(ctx context.Context, tenantSlug, clientID string) (string, error) {
	// TODO: Implementar descifrado con secretbox
	return "", repository.ErrNotImplemented
}

func (r *clientRepo) ValidateClientID(id string) bool {
	return len(id) >= 3 && len(id) <= 64
}

func (r *clientRepo) ValidateRedirectURI(uri string) bool {
	uri = strings.ToLower(strings.TrimSpace(uri))
	if strings.HasPrefix(uri, "https://") {
		return true
	}
	if strings.HasPrefix(uri, "http://localhost") || strings.HasPrefix(uri, "http://127.0.0.1") {
		return true
	}
	return false
}

func (r *clientRepo) IsScopeAllowed(client *repository.Client, scope string) bool {
	for _, s := range client.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func (r *clientRepo) listRaw(tenantSlug string) ([]clientYAML, error) {
	data, err := os.ReadFile(r.conn.clientsFile(tenantSlug))
	if err != nil {
		if os.IsNotExist(err) {
			return []clientYAML{}, nil
		}
		return nil, err
	}
	var raw clientsYAML
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	return raw.Clients, nil
}

func (r *clientRepo) writeClients(tenantSlug string, clients []clientYAML) error {
	raw := clientsYAML{Clients: clients}
	data, err := yaml.Marshal(raw)
	if err != nil {
		return err
	}
	return os.WriteFile(r.conn.clientsFile(tenantSlug), data, 0600)
}

// ─── ScopeRepository ───

type scopeRepo struct{ conn *fsConnection }

func (r *scopeRepo) Create(ctx context.Context, tenantSlug string, input repository.ScopeInput) (*repository.Scope, error) {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	scopes, err := r.listRaw(tenantSlug)
	if err != nil {
		return nil, err
	}

	for _, s := range scopes {
		if s.Name == input.Name {
			return nil, repository.ErrConflict
		}
	}

	now := time.Now()
	newScope := scopeYAML{
		Name:        input.Name,
		Description: input.Description,
		DisplayName: input.DisplayName,
		Claims:      input.Claims,
		DependsOn:   input.DependsOn,
		System:      input.System,
		CreatedAt:   now.Format(time.RFC3339),
		UpdatedAt:   now.Format(time.RFC3339),
	}
	scopes = append(scopes, newScope)

	if err := r.writeScopes(tenantSlug, scopes); err != nil {
		return nil, err
	}

	return &repository.Scope{
		TenantID:    tenantSlug,
		Name:        input.Name,
		Description: input.Description,
		DisplayName: input.DisplayName,
		Claims:      input.Claims,
		DependsOn:   input.DependsOn,
		System:      input.System,
		CreatedAt:   now,
		UpdatedAt:   &now,
	}, nil
}

func (r *scopeRepo) GetByName(ctx context.Context, tenantSlug, name string) (*repository.Scope, error) {
	scopes, err := r.List(ctx, tenantSlug)
	if err != nil {
		return nil, err
	}
	for _, s := range scopes {
		if s.Name == name {
			return &s, nil
		}
	}
	return nil, repository.ErrNotFound
}

func (r *scopeRepo) List(ctx context.Context, tenantSlug string) ([]repository.Scope, error) {
	r.conn.mu.RLock()
	defer r.conn.mu.RUnlock()

	scopes, err := r.listRaw(tenantSlug)
	if err != nil {
		return nil, err
	}

	var result []repository.Scope
	for _, s := range scopes {
		scope := repository.Scope{
			TenantID:    tenantSlug,
			Name:        s.Name,
			Description: s.Description,
			DisplayName: s.DisplayName,
			Claims:      s.Claims,
			DependsOn:   s.DependsOn,
			System:      s.System,
		}
		if s.CreatedAt != "" {
			if t, err := time.Parse(time.RFC3339, s.CreatedAt); err == nil {
				scope.CreatedAt = t
			}
		}
		if s.UpdatedAt != "" {
			if t, err := time.Parse(time.RFC3339, s.UpdatedAt); err == nil {
				scope.UpdatedAt = &t
			}
		}
		result = append(result, scope)
	}
	return result, nil
}

func (r *scopeRepo) Update(ctx context.Context, tenantSlug string, input repository.ScopeInput) (*repository.Scope, error) {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	scopes, err := r.listRaw(tenantSlug)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	found := false
	var updatedScope repository.Scope
	for i, s := range scopes {
		if s.Name == input.Name {
			scopes[i].Description = input.Description
			scopes[i].DisplayName = input.DisplayName
			scopes[i].Claims = input.Claims
			scopes[i].DependsOn = input.DependsOn
			scopes[i].System = input.System
			scopes[i].UpdatedAt = now.Format(time.RFC3339)

			updatedScope = repository.Scope{
				TenantID:    tenantSlug,
				Name:        input.Name,
				Description: input.Description,
				DisplayName: input.DisplayName,
				Claims:      input.Claims,
				DependsOn:   input.DependsOn,
				System:      input.System,
				UpdatedAt:   &now,
			}
			if scopes[i].CreatedAt != "" {
				if t, err := time.Parse(time.RFC3339, scopes[i].CreatedAt); err == nil {
					updatedScope.CreatedAt = t
				}
			}
			found = true
			break
		}
	}

	if !found {
		return nil, repository.ErrNotFound
	}

	if err := r.writeScopes(tenantSlug, scopes); err != nil {
		return nil, err
	}
	return &updatedScope, nil
}

func (r *scopeRepo) Delete(ctx context.Context, tenantSlug, scopeID string) error {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	scopes, err := r.listRaw(tenantSlug)
	if err != nil {
		return err
	}

	var filtered []scopeYAML
	found := false
	for _, s := range scopes {
		if s.Name == scopeID {
			found = true
			continue
		}
		filtered = append(filtered, s)
	}

	if !found {
		return repository.ErrNotFound
	}

	return r.writeScopes(tenantSlug, filtered)
}

func (r *scopeRepo) listRaw(tenantSlug string) ([]scopeYAML, error) {
	data, err := os.ReadFile(r.conn.scopesFile(tenantSlug))
	if err != nil {
		if os.IsNotExist(err) {
			return []scopeYAML{}, nil
		}
		return nil, err
	}
	var raw scopesYAML
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	return raw.Scopes, nil
}

func (r *scopeRepo) Upsert(ctx context.Context, tenantSlug string, input repository.ScopeInput) (*repository.Scope, error) {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	scopes, err := r.listRaw(tenantSlug)
	if err != nil {
		return nil, err
	}

	now := time.Now()

	// Buscar si existe
	for i, s := range scopes {
		if s.Name == input.Name {
			// Existe: actualizar todos los campos
			scopes[i].Description = input.Description
			scopes[i].DisplayName = input.DisplayName
			scopes[i].Claims = input.Claims
			scopes[i].DependsOn = input.DependsOn
			scopes[i].System = input.System
			scopes[i].UpdatedAt = now.Format(time.RFC3339)

			if err := r.writeScopes(tenantSlug, scopes); err != nil {
				return nil, err
			}

			scope := &repository.Scope{
				TenantID:    tenantSlug,
				Name:        input.Name,
				Description: input.Description,
				DisplayName: input.DisplayName,
				Claims:      input.Claims,
				DependsOn:   input.DependsOn,
				System:      input.System,
				UpdatedAt:   &now,
			}
			if scopes[i].CreatedAt != "" {
				if t, err := time.Parse(time.RFC3339, scopes[i].CreatedAt); err == nil {
					scope.CreatedAt = t
				}
			}
			return scope, nil
		}
	}

	// No existe: crear
	newScope := scopeYAML{
		Name:        input.Name,
		Description: input.Description,
		DisplayName: input.DisplayName,
		Claims:      input.Claims,
		DependsOn:   input.DependsOn,
		System:      input.System,
		CreatedAt:   now.Format(time.RFC3339),
		UpdatedAt:   now.Format(time.RFC3339),
	}
	scopes = append(scopes, newScope)

	if err := r.writeScopes(tenantSlug, scopes); err != nil {
		return nil, err
	}

	return &repository.Scope{
		TenantID:    tenantSlug,
		Name:        input.Name,
		Description: input.Description,
		DisplayName: input.DisplayName,
		Claims:      input.Claims,
		DependsOn:   input.DependsOn,
		System:      input.System,
		CreatedAt:   now,
		UpdatedAt:   &now,
	}, nil
}

func (r *scopeRepo) writeScopes(tenantSlug string, scopes []scopeYAML) error {
	raw := scopesYAML{Scopes: scopes}
	data, err := yaml.Marshal(raw)
	if err != nil {
		return err
	}
	return os.WriteFile(r.conn.scopesFile(tenantSlug), data, 0600)
}

// ─── ClaimRepository ───

type claimRepo struct{ conn *fsConnection }

func (r *claimRepo) claimsFile(tenantSlug string) string {
	return filepath.Join(r.conn.tenantPath(tenantSlug), "claims.yaml")
}

func (r *claimRepo) Create(ctx context.Context, tenantSlug string, input repository.ClaimInput) (*repository.ClaimDefinition, error) {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	data, err := r.loadClaimsFile(tenantSlug)
	if err != nil {
		return nil, err
	}

	// Check for duplicate name
	for _, c := range data.CustomClaims {
		if c.Name == input.Name {
			return nil, repository.ErrConflict
		}
	}

	now := time.Now()
	newClaim := customClaimYAML{
		ID:            uuid.New().String(),
		Name:          input.Name,
		Description:   input.Description,
		Source:        input.Source,
		Value:         input.Value,
		AlwaysInclude: input.AlwaysInclude,
		Scopes:        input.Scopes,
		Enabled:       input.Enabled,
		System:        false,
		CreatedAt:     now.Format(time.RFC3339),
		UpdatedAt:     now.Format(time.RFC3339),
	}
	data.CustomClaims = append(data.CustomClaims, newClaim)

	if err := r.saveClaimsFile(tenantSlug, data); err != nil {
		return nil, err
	}

	return &repository.ClaimDefinition{
		ID:          newClaim.ID,
		TenantID:    tenantSlug,
		Name:        input.Name,
		Description: input.Description,
		Scopes:      input.Scopes,
		Enabled:     input.Enabled,
		Required:    input.Required,
		ConfigData:  input.ConfigData,
		System:      false,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

func (r *claimRepo) Get(ctx context.Context, tenantSlug, claimID string) (*repository.ClaimDefinition, error) {
	r.conn.mu.RLock()
	defer r.conn.mu.RUnlock()

	data, err := r.loadClaimsFile(tenantSlug)
	if err != nil {
		return nil, err
	}

	for _, c := range data.CustomClaims {
		if c.ID == claimID {
			return r.yamlToDefinition(tenantSlug, c), nil
		}
	}
	return nil, repository.ErrNotFound
}

func (r *claimRepo) GetByName(ctx context.Context, tenantSlug, name string) (*repository.ClaimDefinition, error) {
	r.conn.mu.RLock()
	defer r.conn.mu.RUnlock()

	data, err := r.loadClaimsFile(tenantSlug)
	if err != nil {
		return nil, err
	}

	for _, c := range data.CustomClaims {
		if c.Name == name {
			return r.yamlToDefinition(tenantSlug, c), nil
		}
	}
	return nil, repository.ErrNotFound
}

func (r *claimRepo) List(ctx context.Context, tenantSlug string) ([]repository.ClaimDefinition, error) {
	r.conn.mu.RLock()
	defer r.conn.mu.RUnlock()

	data, err := r.loadClaimsFile(tenantSlug)
	if err != nil {
		return nil, err
	}

	result := make([]repository.ClaimDefinition, 0, len(data.CustomClaims))
	for _, c := range data.CustomClaims {
		result = append(result, *r.yamlToDefinition(tenantSlug, c))
	}
	return result, nil
}

func (r *claimRepo) Update(ctx context.Context, tenantSlug, claimID string, input repository.ClaimInput) (*repository.ClaimDefinition, error) {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	data, err := r.loadClaimsFile(tenantSlug)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	for i, c := range data.CustomClaims {
		if c.ID == claimID {
			data.CustomClaims[i].Description = input.Description
			data.CustomClaims[i].Source = input.Source
			data.CustomClaims[i].Value = input.Value
			data.CustomClaims[i].Scopes = input.Scopes
			data.CustomClaims[i].Enabled = input.Enabled
			data.CustomClaims[i].Required = input.Required
			data.CustomClaims[i].ConfigData = input.ConfigData
			data.CustomClaims[i].UpdatedAt = now.Format(time.RFC3339)

			if err := r.saveClaimsFile(tenantSlug, data); err != nil {
				return nil, err
			}
			return r.yamlToDefinition(tenantSlug, data.CustomClaims[i]), nil
		}
	}
	return nil, repository.ErrNotFound
}

func (r *claimRepo) Delete(ctx context.Context, tenantSlug, claimID string) error {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	data, err := r.loadClaimsFile(tenantSlug)
	if err != nil {
		return err
	}

	found := false
	filtered := make([]customClaimYAML, 0, len(data.CustomClaims))
	for _, c := range data.CustomClaims {
		if c.ID == claimID {
			found = true
			continue
		}
		filtered = append(filtered, c)
	}

	if !found {
		return repository.ErrNotFound
	}

	data.CustomClaims = filtered
	return r.saveClaimsFile(tenantSlug, data)
}

func (r *claimRepo) GetStandardClaimsConfig(ctx context.Context, tenantSlug string) ([]repository.StandardClaimConfig, error) {
	r.conn.mu.RLock()
	defer r.conn.mu.RUnlock()

	data, err := r.loadClaimsFile(tenantSlug)
	if err != nil {
		return nil, err
	}

	result := make([]repository.StandardClaimConfig, 0, len(data.StandardClaims))
	for _, sc := range data.StandardClaims {
		result = append(result, repository.StandardClaimConfig{
			ClaimName:   sc.Name,
			Description: sc.Description,
			Enabled:     sc.Enabled,
			Scope:       sc.Scope,
		})
	}
	return result, nil
}

func (r *claimRepo) SetStandardClaimEnabled(ctx context.Context, tenantSlug, claimName string, enabled bool) error {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	data, err := r.loadClaimsFile(tenantSlug)
	if err != nil {
		return err
	}

	for i, sc := range data.StandardClaims {
		if sc.Name == claimName {
			data.StandardClaims[i].Enabled = enabled
			return r.saveClaimsFile(tenantSlug, data)
		}
	}
	return repository.ErrNotFound
}

func (r *claimRepo) GetSettings(ctx context.Context, tenantSlug string) (*repository.ClaimsSettings, error) {
	r.conn.mu.RLock()
	defer r.conn.mu.RUnlock()

	data, err := r.loadClaimsFile(tenantSlug)
	if err != nil {
		return nil, err
	}

	return &repository.ClaimsSettings{
		TenantID:             tenantSlug,
		IncludeInAccessToken: data.Settings.IncludeInAccessToken,
		UseNamespacedClaims:  data.Settings.UseNamespacedClaims,
		NamespacePrefix:      data.Settings.NamespacePrefix,
	}, nil
}

func (r *claimRepo) UpdateSettings(ctx context.Context, tenantSlug string, input repository.ClaimsSettingsInput) (*repository.ClaimsSettings, error) {
	r.conn.mu.Lock()
	defer r.conn.mu.Unlock()

	data, err := r.loadClaimsFile(tenantSlug)
	if err != nil {
		return nil, err
	}

	if input.IncludeInAccessToken != nil {
		data.Settings.IncludeInAccessToken = *input.IncludeInAccessToken
	}
	if input.UseNamespacedClaims != nil {
		data.Settings.UseNamespacedClaims = *input.UseNamespacedClaims
	}
	if input.NamespacePrefix != nil {
		data.Settings.NamespacePrefix = input.NamespacePrefix
	}

	if err := r.saveClaimsFile(tenantSlug, data); err != nil {
		return nil, err
	}

	return &repository.ClaimsSettings{
		TenantID:             tenantSlug,
		IncludeInAccessToken: data.Settings.IncludeInAccessToken,
		UseNamespacedClaims:  data.Settings.UseNamespacedClaims,
		NamespacePrefix:      data.Settings.NamespacePrefix,
	}, nil
}

func (r *claimRepo) GetEnabledClaimsForScopes(ctx context.Context, tenantSlug string, scopes []string) ([]repository.ClaimDefinition, error) {
	r.conn.mu.RLock()
	defer r.conn.mu.RUnlock()

	data, err := r.loadClaimsFile(tenantSlug)
	if err != nil {
		return nil, err
	}

	scopeSet := make(map[string]bool)
	for _, s := range scopes {
		scopeSet[s] = true
	}

	var result []repository.ClaimDefinition
	for _, c := range data.CustomClaims {
		if !c.Enabled {
			continue
		}
		if c.AlwaysInclude {
			result = append(result, *r.yamlToDefinition(tenantSlug, c))
			continue
		}
		for _, cs := range c.Scopes {
			if scopeSet[cs] {
				result = append(result, *r.yamlToDefinition(tenantSlug, c))
				break
			}
		}
	}
	return result, nil
}

func (r *claimRepo) loadClaimsFile(tenantSlug string) (*claimsFileYAML, error) {
	path := r.claimsFile(tenantSlug)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return r.defaultClaimsConfig(), nil
		}
		return nil, err
	}
	var cfg claimsFileYAML
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (r *claimRepo) saveClaimsFile(tenantSlug string, data *claimsFileYAML) error {
	raw, err := yaml.Marshal(data)
	if err != nil {
		return err
	}
	return os.WriteFile(r.claimsFile(tenantSlug), raw, 0600)
}

func (r *claimRepo) yamlToDefinition(tenantSlug string, c customClaimYAML) *repository.ClaimDefinition {
	def := &repository.ClaimDefinition{
		ID:            c.ID,
		TenantID:      tenantSlug,
		Name:          c.Name,
		Description:   c.Description,
		Source:        c.Source,
		Value:         c.Value,
		AlwaysInclude: c.AlwaysInclude,
		Scopes:        c.Scopes,
		Enabled:       c.Enabled,
		System:        c.System,
		Required:      c.Required,
		ConfigData:    c.ConfigData,
	}
	if c.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, c.CreatedAt); err == nil {
			def.CreatedAt = t
		}
	}
	if c.UpdatedAt != "" {
		if t, err := time.Parse(time.RFC3339, c.UpdatedAt); err == nil {
			def.UpdatedAt = t
		}
	}
	return def
}

func (r *claimRepo) defaultClaimsConfig() *claimsFileYAML {
	return &claimsFileYAML{
		StandardClaims: []standardClaimYAML{
			{Name: "sub", Description: "Subject identifier", Enabled: true, Scope: "openid"},
			{Name: "email", Description: "User email address", Enabled: true, Scope: "email"},
			{Name: "email_verified", Description: "Email verified flag", Enabled: true, Scope: "email"},
			{Name: "name", Description: "Full name", Enabled: true, Scope: "profile"},
			{Name: "given_name", Description: "First name", Enabled: true, Scope: "profile"},
			{Name: "family_name", Description: "Last name", Enabled: true, Scope: "profile"},
			{Name: "picture", Description: "Profile picture URL", Enabled: true, Scope: "profile"},
			{Name: "locale", Description: "User locale", Enabled: true, Scope: "profile"},
			{Name: "zoneinfo", Description: "Timezone", Enabled: true, Scope: "profile"},
			{Name: "updated_at", Description: "Last update timestamp", Enabled: true, Scope: "profile"},
			{Name: "address", Description: "Physical address", Enabled: true, Scope: "address"},
			{Name: "phone_number", Description: "Phone number", Enabled: true, Scope: "phone"},
			{Name: "phone_number_verified", Description: "Phone verified flag", Enabled: true, Scope: "phone"},
		},
		CustomClaims: []customClaimYAML{},
		Settings: claimsSettingsYAML{
			IncludeInAccessToken: true,
			UseNamespacedClaims:  false,
			NamespacePrefix:      nil,
		},
	}
}

// ─── Claims YAML Types ───

type claimsFileYAML struct {
	StandardClaims []standardClaimYAML `yaml:"standard_claims"`
	CustomClaims   []customClaimYAML   `yaml:"custom_claims"`
	Settings       claimsSettingsYAML  `yaml:"settings"`
}

type standardClaimYAML struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
	Enabled     bool   `yaml:"enabled"`
	Scope       string `yaml:"scope"`
}

type customClaimYAML struct {
	ID            string         `yaml:"id"`
	Name          string         `yaml:"name"`
	Description   string         `yaml:"description,omitempty"`
	Source        string         `yaml:"source"`
	Value         string         `yaml:"value"`
	AlwaysInclude bool           `yaml:"always_include"`
	Scopes        []string       `yaml:"scopes,omitempty"`
	Enabled       bool           `yaml:"enabled"`
	System        bool           `yaml:"system,omitempty"`
	Required      bool           `yaml:"required,omitempty"`
	ConfigData    map[string]any `yaml:"config,omitempty"`
	CreatedAt     string         `yaml:"created_at,omitempty"`
	UpdatedAt     string         `yaml:"updated_at,omitempty"`
}

type claimsSettingsYAML struct {
	IncludeInAccessToken bool    `yaml:"include_in_access_token"`
	UseNamespacedClaims  bool    `yaml:"use_namespaced_claims"`
	NamespacePrefix      *string `yaml:"namespace_prefix,omitempty"`
}

// customOIDCYAML represents a custom OIDC provider for YAML serialization.
type customOIDCYAML struct {
	Alias           string   `yaml:"alias"`
	Enabled         bool     `yaml:"enabled,omitempty"`
	WellKnownURL    string   `yaml:"wellKnownUrl,omitempty"`
	ClientID        string   `yaml:"clientId,omitempty"`
	ClientSecretEnc string   `yaml:"clientSecretEnc,omitempty"`
	Scopes          []string `yaml:"scopes,omitempty"`
}

// ─── YAML Types ───

type tenantYAML struct {
	ID          string             `yaml:"id"`
	Name        string             `yaml:"name"`
	DisplayName string             `yaml:"display_name,omitempty"`
	CreatedAt   time.Time          `yaml:"createdAt,omitempty"`
	UpdatedAt   time.Time          `yaml:"updatedAt,omitempty"`
	Settings    tenantSettingsYAML `yaml:"settings,omitempty"`
}

type tenantSettingsYAML struct {
	LogoURL                     string `yaml:"logoUrl,omitempty"`
	BrandColor                  string `yaml:"brandColor,omitempty"`
	SessionLifetimeSeconds      int    `yaml:"sessionLifetimeSeconds,omitempty"`
	RefreshTokenLifetimeSeconds int    `yaml:"refreshTokenLifetimeSeconds,omitempty"`
	MFAEnabled                  bool   `yaml:"mfaEnabled,omitempty"`
	SocialLoginEnabled          bool   `yaml:"social_login_enabled,omitempty"`
	IssuerMode                  string `yaml:"issuerMode,omitempty"`
	IssuerOverride              string `yaml:"issuerOverride,omitempty"`
	CookiePolicy                *struct {
		Domain   string `yaml:"domain,omitempty"`
		SameSite string `yaml:"sameSite,omitempty"`
		Secure   *bool  `yaml:"secure,omitempty"`
	} `yaml:"cookiePolicy,omitempty"`

	SMTP *struct {
		Host        string `yaml:"host,omitempty"`
		Port        int    `yaml:"port,omitempty"`
		Username    string `yaml:"username,omitempty"`
		PasswordEnc string `yaml:"passwordEnc,omitempty"`
		FromEmail   string `yaml:"fromEmail,omitempty"`
		UseTLS      bool   `yaml:"useTLS,omitempty"`
	} `yaml:"smtp,omitempty"`

	UserDB *struct {
		Driver     string `yaml:"driver,omitempty"`
		DSNEnc     string `yaml:"dsnEnc,omitempty"`
		DSN        string `yaml:"dsn,omitempty"`
		Schema     string `yaml:"schema,omitempty"`
		ManualMode bool   `yaml:"manualMode,omitempty"`
	} `yaml:"userDb,omitempty"`

	Webhooks []webhookYAML `yaml:"webhooks,omitempty"`

	Cache *struct {
		Enabled  bool   `yaml:"enabled"`
		Driver   string `yaml:"driver,omitempty"`
		Host     string `yaml:"host,omitempty"`
		Port     int    `yaml:"port,omitempty"`
		Password string `yaml:"password,omitempty"`
		PassEnc  string `yaml:"passEnc,omitempty"`
		DB       int    `yaml:"db,omitempty"`
		Prefix   string `yaml:"prefix,omitempty"`
	} `yaml:"cache,omitempty"`

	SocialProviders *struct {
		// Google
		GoogleEnabled   bool   `yaml:"googleEnabled,omitempty"`
		GoogleClient    string `yaml:"googleClient,omitempty"`
		GoogleSecretEnc string `yaml:"googleSecretEnc,omitempty"`
		// GitHub
		GitHubEnabled   bool   `yaml:"githubEnabled,omitempty"`
		GitHubClient    string `yaml:"githubClient,omitempty"`
		GitHubSecretEnc string `yaml:"githubSecretEnc,omitempty"`
		// Facebook
		FacebookEnabled   bool   `yaml:"facebookEnabled,omitempty"`
		FacebookClient    string `yaml:"facebookClient,omitempty"`
		FacebookSecretEnc string `yaml:"facebookSecretEnc,omitempty"`
		// Discord
		DiscordEnabled   bool   `yaml:"discordEnabled,omitempty"`
		DiscordClient    string `yaml:"discordClient,omitempty"`
		DiscordSecretEnc string `yaml:"discordSecretEnc,omitempty"`
		// Microsoft
		MicrosoftEnabled   bool   `yaml:"microsoftEnabled,omitempty"`
		MicrosoftClient    string `yaml:"microsoftClient,omitempty"`
		MicrosoftSecretEnc string `yaml:"microsoftSecretEnc,omitempty"`
		MicrosoftTenant    string `yaml:"microsoftTenant,omitempty"`
		// LinkedIn
		LinkedInEnabled   bool   `yaml:"linkedinEnabled,omitempty"`
		LinkedInClient    string `yaml:"linkedinClient,omitempty"`
		LinkedInSecretEnc string `yaml:"linkedinSecretEnc,omitempty"`
		// Apple
		AppleEnabled       bool   `yaml:"appleEnabled,omitempty"`
		AppleClientID      string `yaml:"appleClient,omitempty"`
		AppleTeamID        string `yaml:"appleTeamId,omitempty"`
		AppleKeyID         string `yaml:"appleKeyId,omitempty"`
		ApplePrivateKeyEnc string `yaml:"applePrivateKeyEnc,omitempty"`
		// Custom OIDC
		CustomOIDCProviders []customOIDCYAML `yaml:"customOidcProviders,omitempty"`
	} `yaml:"socialProviders,omitempty"`

	Security *struct {
		PasswordMinLength      int  `yaml:"passwordMinLength,omitempty"`
		RequireUppercase       bool `yaml:"requireUppercase,omitempty"`
		RequireLowercase       bool `yaml:"requireLowercase,omitempty"`
		RequireNumbers         bool `yaml:"requireNumbers,omitempty"`
		RequireSpecialChars    bool `yaml:"requireSpecialChars,omitempty"`
		MaxHistory             int  `yaml:"maxHistory,omitempty"`
		BreachDetection        bool `yaml:"breachDetection,omitempty"`
		MFARequired            bool `yaml:"mfaRequired,omitempty"`
		MaxLoginAttempts       int  `yaml:"maxLoginAttempts,omitempty"`
		LockoutDurationMinutes int  `yaml:"lockoutDurationMinutes,omitempty"`
	} `yaml:"security,omitempty"`

	Passwordless *struct {
		MagicLink *struct {
			Enabled      bool `yaml:"enabled,omitempty"`
			TTLSeconds   int  `yaml:"ttlSeconds,omitempty"`
			AutoRegister bool `yaml:"autoRegister,omitempty"`
		} `yaml:"magicLink,omitempty"`
		OTP *struct {
			Enabled        bool `yaml:"enabled,omitempty"`
			TTLSeconds     int  `yaml:"ttlSeconds,omitempty"`
			Length         int  `yaml:"length,omitempty"`
			AutoRegister   bool `yaml:"autoRegister,omitempty"`
			DailyMaxEmails int  `yaml:"dailyMaxEmails,omitempty"`
		} `yaml:"otp,omitempty"`
	} `yaml:"passwordless,omitempty"`

	UserFields []userFieldYAML `yaml:"userFields,omitempty"`

	AuditRetentionDays int    `yaml:"auditRetentionDays,omitempty"` // 0 = disable auto-purge
	SecondaryColor     string `yaml:"secondaryColor,omitempty"`
	FaviconURL         string `yaml:"faviconUrl,omitempty"`

	ConsentPolicy *consentPolicyYAML `yaml:"consentPolicy,omitempty"`
	Mailing       *mailingYAML       `yaml:"mailing,omitempty"`
	MFA           *mfaYAML           `yaml:"mfa,omitempty"`
	WebAuthn      *webAuthnYAML      `yaml:"webAuthn,omitempty"`
}

// userFieldYAML representa un campo custom de usuario para serialización YAML.
type userFieldYAML struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type"`
	Required    bool   `yaml:"required,omitempty"`
	Unique      bool   `yaml:"unique,omitempty"`
	Indexed     bool   `yaml:"indexed,omitempty"`
	Description string `yaml:"description,omitempty"`
}

type consentPolicyYAML struct {
	ConsentMode                   string `yaml:"consentMode,omitempty"`
	ExpirationDays                *int   `yaml:"expirationDays,omitempty"`
	RepromptDays                  *int   `yaml:"repromptDays,omitempty"`
	RememberScopeDecisions        bool   `yaml:"rememberScopeDecisions,omitempty"`
	ShowConsentScreen             bool   `yaml:"showConsentScreen,omitempty"`
	AllowSkipConsentForFirstParty bool   `yaml:"allowSkipConsentForFirstParty,omitempty"`
}

type emailTemplateYAML struct {
	Subject string `yaml:"subject,omitempty"`
	Body    string `yaml:"body,omitempty"`
}

type mailingYAML struct {
	// map[lang]map[templateID]emailTemplateYAML
	Templates map[string]map[string]emailTemplateYAML `yaml:"templates,omitempty"`
}

type smsConfigYAML struct {
	Provider            string `yaml:"provider,omitempty"`
	TwilioAccountSIDEnc string `yaml:"twilioAccountSidEnc,omitempty"`
	TwilioAuthTokenEnc  string `yaml:"twilioAuthTokenEnc,omitempty"`
	TwilioFrom          string `yaml:"twilioFrom,omitempty"`
	VonageAPIKeyEnc     string `yaml:"vonageApiKeyEnc,omitempty"`
	VonageAPISecretEnc  string `yaml:"vonageApiSecretEnc,omitempty"`
	VonageFrom          string `yaml:"vonageFrom,omitempty"`
}

type mfaYAML struct {
	TOTPIssuer string         `yaml:"totpIssuer,omitempty"`
	TOTPWindow int            `yaml:"totpWindow,omitempty"`
	SMS        *smsConfigYAML `yaml:"sms,omitempty"`
}

type webAuthnYAML struct {
	RPID          string   `yaml:"rpid,omitempty"`
	RPOrigins     []string `yaml:"rpOrigins,omitempty"`
	RPDisplayName string   `yaml:"rpDisplayName,omitempty"`
}

func (t *tenantYAML) toRepository(slug string) *repository.Tenant {
	tenant := &repository.Tenant{
		ID:          t.ID,
		Slug:        slug,
		Name:        t.Name,
		DisplayName: t.DisplayName,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
		Settings: repository.TenantSettings{
			LogoURL:                     t.Settings.LogoURL,
			BrandColor:                  t.Settings.BrandColor,
			SecondaryColor:              t.Settings.SecondaryColor,
			FaviconURL:                  t.Settings.FaviconURL,
			SessionLifetimeSeconds:      t.Settings.SessionLifetimeSeconds,
			RefreshTokenLifetimeSeconds: t.Settings.RefreshTokenLifetimeSeconds,
			MFAEnabled:                  t.Settings.MFAEnabled,
			SocialLoginEnabled:          t.Settings.SocialLoginEnabled,
			IssuerMode:                  t.Settings.IssuerMode,
			IssuerOverride:              t.Settings.IssuerOverride,
			AuditRetentionDays:          t.Settings.AuditRetentionDays,
		},
	}

	if t.Settings.CookiePolicy != nil {
		tenant.Settings.CookiePolicy = &repository.CookiePolicy{
			Domain:   t.Settings.CookiePolicy.Domain,
			SameSite: t.Settings.CookiePolicy.SameSite,
			Secure:   t.Settings.CookiePolicy.Secure,
		}
	}

	if t.Settings.SMTP != nil {
		tenant.Settings.SMTP = &repository.SMTPSettings{
			Host:        t.Settings.SMTP.Host,
			Port:        t.Settings.SMTP.Port,
			Username:    t.Settings.SMTP.Username,
			PasswordEnc: t.Settings.SMTP.PasswordEnc,
			FromEmail:   t.Settings.SMTP.FromEmail,
			UseTLS:      t.Settings.SMTP.UseTLS,
		}
	}

	if t.Settings.UserDB != nil {
		tenant.Settings.UserDB = &repository.UserDBSettings{
			Driver:     t.Settings.UserDB.Driver,
			DSNEnc:     t.Settings.UserDB.DSNEnc,
			DSN:        t.Settings.UserDB.DSN,
			Schema:     t.Settings.UserDB.Schema,
			ManualMode: t.Settings.UserDB.ManualMode,
		}
	}

	if t.Settings.Cache != nil {
		tenant.Settings.Cache = &repository.CacheSettings{
			Enabled:  t.Settings.Cache.Enabled,
			Driver:   t.Settings.Cache.Driver,
			Host:     t.Settings.Cache.Host,
			Port:     t.Settings.Cache.Port,
			Password: t.Settings.Cache.Password,
			PassEnc:  t.Settings.Cache.PassEnc,
			DB:       t.Settings.Cache.DB,
			Prefix:   t.Settings.Cache.Prefix,
		}
	}

	if t.Settings.SocialProviders != nil {
		sp := t.Settings.SocialProviders
		socialCfg := &repository.SocialConfig{
			// Google
			GoogleEnabled:   sp.GoogleEnabled,
			GoogleClient:    sp.GoogleClient,
			GoogleSecretEnc: sp.GoogleSecretEnc,
			// GitHub
			GitHubEnabled:   sp.GitHubEnabled,
			GitHubClient:    sp.GitHubClient,
			GitHubSecretEnc: sp.GitHubSecretEnc,
			// Facebook
			FacebookEnabled:   sp.FacebookEnabled,
			FacebookClient:    sp.FacebookClient,
			FacebookSecretEnc: sp.FacebookSecretEnc,
			// Discord
			DiscordEnabled:   sp.DiscordEnabled,
			DiscordClient:    sp.DiscordClient,
			DiscordSecretEnc: sp.DiscordSecretEnc,
			// Microsoft
			MicrosoftEnabled:   sp.MicrosoftEnabled,
			MicrosoftClient:    sp.MicrosoftClient,
			MicrosoftSecretEnc: sp.MicrosoftSecretEnc,
			MicrosoftTenant:    sp.MicrosoftTenant,
			// LinkedIn
			LinkedInEnabled:   sp.LinkedInEnabled,
			LinkedInClient:    sp.LinkedInClient,
			LinkedInSecretEnc: sp.LinkedInSecretEnc,
			// Apple
			AppleEnabled:       sp.AppleEnabled,
			AppleClientID:      sp.AppleClientID,
			AppleTeamID:        sp.AppleTeamID,
			AppleKeyID:         sp.AppleKeyID,
			ApplePrivateKeyEnc: sp.ApplePrivateKeyEnc,
		}
		// Custom OIDC
		for _, c := range sp.CustomOIDCProviders {
			socialCfg.CustomOIDCProviders = append(socialCfg.CustomOIDCProviders, repository.CustomOIDCConfig{
				Alias:           c.Alias,
				Enabled:         c.Enabled,
				WellKnownURL:    c.WellKnownURL,
				ClientID:        c.ClientID,
				ClientSecretEnc: c.ClientSecretEnc,
				Scopes:          c.Scopes,
			})
		}
		tenant.Settings.SocialProviders = socialCfg
	}

	if t.Settings.Security != nil {
		tenant.Settings.Security = &repository.SecurityPolicy{
			PasswordMinLength:      t.Settings.Security.PasswordMinLength,
			RequireUppercase:       t.Settings.Security.RequireUppercase,
			RequireLowercase:       t.Settings.Security.RequireLowercase,
			RequireNumbers:         t.Settings.Security.RequireNumbers,
			RequireSpecialChars:    t.Settings.Security.RequireSpecialChars,
			MaxHistory:             t.Settings.Security.MaxHistory,
			BreachDetection:        t.Settings.Security.BreachDetection,
			MFARequired:            t.Settings.Security.MFARequired,
			MaxLoginAttempts:       t.Settings.Security.MaxLoginAttempts,
			LockoutDurationMinutes: t.Settings.Security.LockoutDurationMinutes,
		}
	}

	if t.Settings.Passwordless != nil {
		tenant.Settings.Passwordless = &repository.PasswordlessConfig{}
		if t.Settings.Passwordless.MagicLink != nil {
			tenant.Settings.Passwordless.MagicLink = repository.MagicLinkConfig{
				Enabled:      t.Settings.Passwordless.MagicLink.Enabled,
				TTLSeconds:   t.Settings.Passwordless.MagicLink.TTLSeconds,
				AutoRegister: t.Settings.Passwordless.MagicLink.AutoRegister,
			}
		}
		if t.Settings.Passwordless.OTP != nil {
			tenant.Settings.Passwordless.OTP = repository.OTPConfig{
				Enabled:        t.Settings.Passwordless.OTP.Enabled,
				TTLSeconds:     t.Settings.Passwordless.OTP.TTLSeconds,
				Length:         t.Settings.Passwordless.OTP.Length,
				AutoRegister:   t.Settings.Passwordless.OTP.AutoRegister,
				DailyMaxEmails: t.Settings.Passwordless.OTP.DailyMaxEmails,
			}
		}
	}

	// UserFields
	if len(t.Settings.UserFields) > 0 {
		tenant.Settings.UserFields = make([]repository.UserFieldDefinition, len(t.Settings.UserFields))
		for i, uf := range t.Settings.UserFields {
			tenant.Settings.UserFields[i] = repository.UserFieldDefinition{
				Name:        uf.Name,
				Type:        uf.Type,
				Required:    uf.Required,
				Unique:      uf.Unique,
				Indexed:     uf.Indexed,
				Description: uf.Description,
			}
		}
	}

	// Webhooks
	if len(t.Settings.Webhooks) > 0 {
		tenant.Settings.Webhooks = make([]repository.WebhookConfig, len(t.Settings.Webhooks))
		for i, wh := range t.Settings.Webhooks {
			tenant.Settings.Webhooks[i] = repository.WebhookConfig{
				ID:        wh.ID,
				URL:       wh.URL,
				SecretEnc: wh.SecretEnc,
				Events:    wh.Events,
				Enabled:   wh.Enabled,
			}
		}
	}

	// ConsentPolicy
	if t.Settings.ConsentPolicy != nil {
		cp := t.Settings.ConsentPolicy
		tenant.Settings.ConsentPolicy = &repository.ConsentPolicySettings{
			ConsentMode:                   cp.ConsentMode,
			ExpirationDays:                cp.ExpirationDays,
			RepromptDays:                  cp.RepromptDays,
			RememberScopeDecisions:        cp.RememberScopeDecisions,
			ShowConsentScreen:             cp.ShowConsentScreen,
			AllowSkipConsentForFirstParty: cp.AllowSkipConsentForFirstParty,
		}
	}

	// Mailing
	if t.Settings.Mailing != nil && len(t.Settings.Mailing.Templates) > 0 {
		mailing := &repository.MailingSettings{
			Templates: make(map[string]map[string]repository.EmailTemplate),
		}
		for lang, langTpls := range t.Settings.Mailing.Templates {
			if mailing.Templates[lang] == nil {
				mailing.Templates[lang] = make(map[string]repository.EmailTemplate)
			}
			for tplID, tpl := range langTpls {
				mailing.Templates[lang][tplID] = repository.EmailTemplate{
					Subject: tpl.Subject,
					Body:    tpl.Body,
				}
			}
		}
		tenant.Settings.Mailing = mailing
	}

	// MFA
	if t.Settings.MFA != nil {
		mfa := &repository.MFAConfig{
			TOTPIssuer: t.Settings.MFA.TOTPIssuer,
			TOTPWindow: t.Settings.MFA.TOTPWindow,
		}
		if t.Settings.MFA.SMS != nil {
			sms := t.Settings.MFA.SMS
			mfa.SMS = &repository.TenantSMSConfig{
				Provider:            sms.Provider,
				TwilioAccountSIDEnc: sms.TwilioAccountSIDEnc,
				TwilioAuthTokenEnc:  sms.TwilioAuthTokenEnc,
				TwilioFrom:          sms.TwilioFrom,
				VonageAPIKeyEnc:     sms.VonageAPIKeyEnc,
				VonageAPISecretEnc:  sms.VonageAPISecretEnc,
				VonageFrom:          sms.VonageFrom,
			}
		}
		tenant.Settings.MFA = mfa
	}

	// WebAuthn
	if t.Settings.WebAuthn != nil && (t.Settings.WebAuthn.RPID != "" || len(t.Settings.WebAuthn.RPOrigins) > 0) {
		tenant.Settings.WebAuthn = repository.WebAuthnConfig{
			RPID:          t.Settings.WebAuthn.RPID,
			RPOrigins:     t.Settings.WebAuthn.RPOrigins,
			RPDisplayName: t.Settings.WebAuthn.RPDisplayName,
		}
	}

	return tenant
}

func toTenantYAML(t *repository.Tenant) *tenantYAML {
	y := &tenantYAML{
		ID:          t.ID,
		Name:        t.Name,
		DisplayName: t.DisplayName,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   time.Now(),
		Settings: tenantSettingsYAML{
			LogoURL:                     t.Settings.LogoURL,
			BrandColor:                  t.Settings.BrandColor,
			SecondaryColor:              t.Settings.SecondaryColor,
			FaviconURL:                  t.Settings.FaviconURL,
			SessionLifetimeSeconds:      t.Settings.SessionLifetimeSeconds,
			RefreshTokenLifetimeSeconds: t.Settings.RefreshTokenLifetimeSeconds,
			MFAEnabled:                  t.Settings.MFAEnabled,
			SocialLoginEnabled:          t.Settings.SocialLoginEnabled,
			IssuerMode:                  t.Settings.IssuerMode,
			IssuerOverride:              t.Settings.IssuerOverride,
			AuditRetentionDays:          t.Settings.AuditRetentionDays,
		},
	}

	if t.Settings.CookiePolicy != nil {
		y.Settings.CookiePolicy = &struct {
			Domain   string `yaml:"domain,omitempty"`
			SameSite string `yaml:"sameSite,omitempty"`
			Secure   *bool  `yaml:"secure,omitempty"`
		}{
			Domain:   t.Settings.CookiePolicy.Domain,
			SameSite: t.Settings.CookiePolicy.SameSite,
			Secure:   t.Settings.CookiePolicy.Secure,
		}
	}

	// SMTP
	if t.Settings.SMTP != nil {
		y.Settings.SMTP = &struct {
			Host        string `yaml:"host,omitempty"`
			Port        int    `yaml:"port,omitempty"`
			Username    string `yaml:"username,omitempty"`
			PasswordEnc string `yaml:"passwordEnc,omitempty"`
			FromEmail   string `yaml:"fromEmail,omitempty"`
			UseTLS      bool   `yaml:"useTLS,omitempty"`
		}{
			Host:        t.Settings.SMTP.Host,
			Port:        t.Settings.SMTP.Port,
			Username:    t.Settings.SMTP.Username,
			PasswordEnc: t.Settings.SMTP.PasswordEnc,
			FromEmail:   t.Settings.SMTP.FromEmail,
			UseTLS:      t.Settings.SMTP.UseTLS,
		}
	}

	// UserDB
	if t.Settings.UserDB != nil {
		y.Settings.UserDB = &struct {
			Driver     string `yaml:"driver,omitempty"`
			DSNEnc     string `yaml:"dsnEnc,omitempty"`
			DSN        string `yaml:"dsn,omitempty"`
			Schema     string `yaml:"schema,omitempty"`
			ManualMode bool   `yaml:"manualMode,omitempty"`
		}{
			Driver:     t.Settings.UserDB.Driver,
			DSNEnc:     t.Settings.UserDB.DSNEnc,
			DSN:        t.Settings.UserDB.DSN,
			Schema:     t.Settings.UserDB.Schema,
			ManualMode: t.Settings.UserDB.ManualMode,
		}
	}

	// Cache
	if t.Settings.Cache != nil {
		y.Settings.Cache = &struct {
			Enabled  bool   `yaml:"enabled"`
			Driver   string `yaml:"driver,omitempty"`
			Host     string `yaml:"host,omitempty"`
			Port     int    `yaml:"port,omitempty"`
			Password string `yaml:"password,omitempty"`
			PassEnc  string `yaml:"passEnc,omitempty"`
			DB       int    `yaml:"db,omitempty"`
			Prefix   string `yaml:"prefix,omitempty"`
		}{
			Enabled:  t.Settings.Cache.Enabled,
			Driver:   t.Settings.Cache.Driver,
			Host:     t.Settings.Cache.Host,
			Port:     t.Settings.Cache.Port,
			Password: t.Settings.Cache.Password,
			PassEnc:  t.Settings.Cache.PassEnc,
			DB:       t.Settings.Cache.DB,
			Prefix:   t.Settings.Cache.Prefix,
		}
	}

	// SocialProviders
	if t.Settings.SocialProviders != nil {
		sp := t.Settings.SocialProviders
		yamlSP := &struct {
			// Google
			GoogleEnabled   bool   `yaml:"googleEnabled,omitempty"`
			GoogleClient    string `yaml:"googleClient,omitempty"`
			GoogleSecretEnc string `yaml:"googleSecretEnc,omitempty"`
			// GitHub
			GitHubEnabled   bool   `yaml:"githubEnabled,omitempty"`
			GitHubClient    string `yaml:"githubClient,omitempty"`
			GitHubSecretEnc string `yaml:"githubSecretEnc,omitempty"`
			// Facebook
			FacebookEnabled   bool   `yaml:"facebookEnabled,omitempty"`
			FacebookClient    string `yaml:"facebookClient,omitempty"`
			FacebookSecretEnc string `yaml:"facebookSecretEnc,omitempty"`
			// Discord
			DiscordEnabled   bool   `yaml:"discordEnabled,omitempty"`
			DiscordClient    string `yaml:"discordClient,omitempty"`
			DiscordSecretEnc string `yaml:"discordSecretEnc,omitempty"`
			// Microsoft
			MicrosoftEnabled   bool   `yaml:"microsoftEnabled,omitempty"`
			MicrosoftClient    string `yaml:"microsoftClient,omitempty"`
			MicrosoftSecretEnc string `yaml:"microsoftSecretEnc,omitempty"`
			MicrosoftTenant    string `yaml:"microsoftTenant,omitempty"`
			// LinkedIn
			LinkedInEnabled   bool   `yaml:"linkedinEnabled,omitempty"`
			LinkedInClient    string `yaml:"linkedinClient,omitempty"`
			LinkedInSecretEnc string `yaml:"linkedinSecretEnc,omitempty"`
			// Apple
			AppleEnabled       bool   `yaml:"appleEnabled,omitempty"`
			AppleClientID      string `yaml:"appleClient,omitempty"`
			AppleTeamID        string `yaml:"appleTeamId,omitempty"`
			AppleKeyID         string `yaml:"appleKeyId,omitempty"`
			ApplePrivateKeyEnc string `yaml:"applePrivateKeyEnc,omitempty"`
			// Custom OIDC
			CustomOIDCProviders []customOIDCYAML `yaml:"customOidcProviders,omitempty"`
		}{
			// Google
			GoogleEnabled:   sp.GoogleEnabled,
			GoogleClient:    sp.GoogleClient,
			GoogleSecretEnc: sp.GoogleSecretEnc,
			// GitHub
			GitHubEnabled:   sp.GitHubEnabled,
			GitHubClient:    sp.GitHubClient,
			GitHubSecretEnc: sp.GitHubSecretEnc,
			// Facebook
			FacebookEnabled:   sp.FacebookEnabled,
			FacebookClient:    sp.FacebookClient,
			FacebookSecretEnc: sp.FacebookSecretEnc,
			// Discord
			DiscordEnabled:   sp.DiscordEnabled,
			DiscordClient:    sp.DiscordClient,
			DiscordSecretEnc: sp.DiscordSecretEnc,
			// Microsoft
			MicrosoftEnabled:   sp.MicrosoftEnabled,
			MicrosoftClient:    sp.MicrosoftClient,
			MicrosoftSecretEnc: sp.MicrosoftSecretEnc,
			MicrosoftTenant:    sp.MicrosoftTenant,
			// LinkedIn
			LinkedInEnabled:   sp.LinkedInEnabled,
			LinkedInClient:    sp.LinkedInClient,
			LinkedInSecretEnc: sp.LinkedInSecretEnc,
			// Apple
			AppleEnabled:       sp.AppleEnabled,
			AppleClientID:      sp.AppleClientID,
			AppleTeamID:        sp.AppleTeamID,
			AppleKeyID:         sp.AppleKeyID,
			ApplePrivateKeyEnc: sp.ApplePrivateKeyEnc,
		}
		// Custom OIDC
		for _, c := range sp.CustomOIDCProviders {
			yamlSP.CustomOIDCProviders = append(yamlSP.CustomOIDCProviders, customOIDCYAML{
				Alias:           c.Alias,
				Enabled:         c.Enabled,
				WellKnownURL:    c.WellKnownURL,
				ClientID:        c.ClientID,
				ClientSecretEnc: c.ClientSecretEnc,
				Scopes:          c.Scopes,
			})
		}
		y.Settings.SocialProviders = yamlSP
	}

	// Security
	if t.Settings.Security != nil {
		y.Settings.Security = &struct {
			PasswordMinLength      int  `yaml:"passwordMinLength,omitempty"`
			RequireUppercase       bool `yaml:"requireUppercase,omitempty"`
			RequireLowercase       bool `yaml:"requireLowercase,omitempty"`
			RequireNumbers         bool `yaml:"requireNumbers,omitempty"`
			RequireSpecialChars    bool `yaml:"requireSpecialChars,omitempty"`
			MaxHistory             int  `yaml:"maxHistory,omitempty"`
			BreachDetection        bool `yaml:"breachDetection,omitempty"`
			MFARequired            bool `yaml:"mfaRequired,omitempty"`
			MaxLoginAttempts       int  `yaml:"maxLoginAttempts,omitempty"`
			LockoutDurationMinutes int  `yaml:"lockoutDurationMinutes,omitempty"`
		}{
			PasswordMinLength:      t.Settings.Security.PasswordMinLength,
			RequireUppercase:       t.Settings.Security.RequireUppercase,
			RequireLowercase:       t.Settings.Security.RequireLowercase,
			RequireNumbers:         t.Settings.Security.RequireNumbers,
			RequireSpecialChars:    t.Settings.Security.RequireSpecialChars,
			MaxHistory:             t.Settings.Security.MaxHistory,
			BreachDetection:        t.Settings.Security.BreachDetection,
			MFARequired:            t.Settings.Security.MFARequired,
			MaxLoginAttempts:       t.Settings.Security.MaxLoginAttempts,
			LockoutDurationMinutes: t.Settings.Security.LockoutDurationMinutes,
		}
	}

	if t.Settings.Passwordless != nil {
		y.Settings.Passwordless = &struct {
			MagicLink *struct {
				Enabled      bool `yaml:"enabled,omitempty"`
				TTLSeconds   int  `yaml:"ttlSeconds,omitempty"`
				AutoRegister bool `yaml:"autoRegister,omitempty"`
			} `yaml:"magicLink,omitempty"`
			OTP *struct {
				Enabled        bool `yaml:"enabled,omitempty"`
				TTLSeconds     int  `yaml:"ttlSeconds,omitempty"`
				Length         int  `yaml:"length,omitempty"`
				AutoRegister   bool `yaml:"autoRegister,omitempty"`
				DailyMaxEmails int  `yaml:"dailyMaxEmails,omitempty"`
			} `yaml:"otp,omitempty"`
		}{}

		y.Settings.Passwordless.MagicLink = &struct {
			Enabled      bool `yaml:"enabled,omitempty"`
			TTLSeconds   int  `yaml:"ttlSeconds,omitempty"`
			AutoRegister bool `yaml:"autoRegister,omitempty"`
		}{
			Enabled:      t.Settings.Passwordless.MagicLink.Enabled,
			TTLSeconds:   t.Settings.Passwordless.MagicLink.TTLSeconds,
			AutoRegister: t.Settings.Passwordless.MagicLink.AutoRegister,
		}
		y.Settings.Passwordless.OTP = &struct {
			Enabled        bool `yaml:"enabled,omitempty"`
			TTLSeconds     int  `yaml:"ttlSeconds,omitempty"`
			Length         int  `yaml:"length,omitempty"`
			AutoRegister   bool `yaml:"autoRegister,omitempty"`
			DailyMaxEmails int  `yaml:"dailyMaxEmails,omitempty"`
		}{
			Enabled:        t.Settings.Passwordless.OTP.Enabled,
			TTLSeconds:     t.Settings.Passwordless.OTP.TTLSeconds,
			Length:         t.Settings.Passwordless.OTP.Length,
			AutoRegister:   t.Settings.Passwordless.OTP.AutoRegister,
			DailyMaxEmails: t.Settings.Passwordless.OTP.DailyMaxEmails,
		}
	}

	// UserFields
	if len(t.Settings.UserFields) > 0 {
		y.Settings.UserFields = make([]userFieldYAML, len(t.Settings.UserFields))
		for i, uf := range t.Settings.UserFields {
			y.Settings.UserFields[i] = userFieldYAML{
				Name:        uf.Name,
				Type:        uf.Type,
				Required:    uf.Required,
				Unique:      uf.Unique,
				Indexed:     uf.Indexed,
				Description: uf.Description,
			}
		}
	}

	// Webhooks
	if len(t.Settings.Webhooks) > 0 {
		y.Settings.Webhooks = make([]webhookYAML, len(t.Settings.Webhooks))
		for i, wh := range t.Settings.Webhooks {
			y.Settings.Webhooks[i] = webhookYAML{
				ID:        wh.ID,
				URL:       wh.URL,
				SecretEnc: wh.SecretEnc,
				Events:    wh.Events,
				Enabled:   wh.Enabled,
			}
		}
	}

	// ConsentPolicy
	if t.Settings.ConsentPolicy != nil {
		cp := t.Settings.ConsentPolicy
		y.Settings.ConsentPolicy = &consentPolicyYAML{
			ConsentMode:                   cp.ConsentMode,
			ExpirationDays:                cp.ExpirationDays,
			RepromptDays:                  cp.RepromptDays,
			RememberScopeDecisions:        cp.RememberScopeDecisions,
			ShowConsentScreen:             cp.ShowConsentScreen,
			AllowSkipConsentForFirstParty: cp.AllowSkipConsentForFirstParty,
		}
	}

	// Mailing
	if t.Settings.Mailing != nil && len(t.Settings.Mailing.Templates) > 0 {
		mailing := &mailingYAML{
			Templates: make(map[string]map[string]emailTemplateYAML),
		}
		for lang, langTpls := range t.Settings.Mailing.Templates {
			if mailing.Templates[lang] == nil {
				mailing.Templates[lang] = make(map[string]emailTemplateYAML)
			}
			for tplID, tpl := range langTpls {
				mailing.Templates[lang][tplID] = emailTemplateYAML{
					Subject: tpl.Subject,
					Body:    tpl.Body,
				}
			}
		}
		y.Settings.Mailing = mailing
	}

	// MFA config
	if t.Settings.MFA != nil {
		mfa := &mfaYAML{
			TOTPIssuer: t.Settings.MFA.TOTPIssuer,
			TOTPWindow: t.Settings.MFA.TOTPWindow,
		}
		if t.Settings.MFA.SMS != nil {
			sms := t.Settings.MFA.SMS
			mfa.SMS = &smsConfigYAML{
				Provider:            sms.Provider,
				TwilioAccountSIDEnc: sms.TwilioAccountSIDEnc,
				TwilioAuthTokenEnc:  sms.TwilioAuthTokenEnc,
				TwilioFrom:          sms.TwilioFrom,
				VonageAPIKeyEnc:     sms.VonageAPIKeyEnc,
				VonageAPISecretEnc:  sms.VonageAPISecretEnc,
				VonageFrom:          sms.VonageFrom,
			}
		}
		y.Settings.MFA = mfa
	}

	// WebAuthn
	if t.Settings.WebAuthn.RPID != "" || len(t.Settings.WebAuthn.RPOrigins) > 0 {
		y.Settings.WebAuthn = &webAuthnYAML{
			RPID:          t.Settings.WebAuthn.RPID,
			RPOrigins:     t.Settings.WebAuthn.RPOrigins,
			RPDisplayName: t.Settings.WebAuthn.RPDisplayName,
		}
	}

	return y
}

type webhookYAML struct {
	ID        string   `yaml:"id"`
	URL       string   `yaml:"url"`
	SecretEnc string   `yaml:"secretEnc"`
	Events    []string `yaml:"events"`
	Enabled   bool     `yaml:"enabled"`
}

type clientsYAML struct {
	Clients []clientYAML `yaml:"clients"`
}

type clientYAML struct {
	ClientID                 string         `yaml:"clientId"`
	Name                     string         `yaml:"name"`
	Type                     string         `yaml:"type"`
	AuthProfile              string         `yaml:"authProfile,omitempty"`
	RedirectURIs             []string       `yaml:"redirectUris"`
	AllowedOrigins           []string       `yaml:"allowedOrigins,omitempty"`
	Providers                []string       `yaml:"providers,omitempty"`
	Scopes                   []string       `yaml:"scopes,omitempty"`
	SecretEnc                string         `yaml:"secretEnc,omitempty"`
	RequireEmailVerification bool           `yaml:"requireEmailVerification,omitempty"`
	ResetPasswordURL         string         `yaml:"resetPasswordURL,omitempty"`
	VerifyEmailURL           string         `yaml:"verifyEmailURL,omitempty"`
	ClaimSchema              map[string]any `yaml:"claimSchema,omitempty"`
	ClaimMapping             map[string]any `yaml:"claimMapping,omitempty"`
	GrantTypes               []string       `yaml:"grantTypes,omitempty"`
	AccessTokenTTL           int            `yaml:"accessTokenTTL,omitempty"`
	RefreshTokenTTL          int            `yaml:"refreshTokenTTL,omitempty"`
	IDTokenTTL               int            `yaml:"idTokenTTL,omitempty"`
	PostLogoutURIs           []string       `yaml:"postLogoutURIs,omitempty"`
	Description              string         `yaml:"description,omitempty"`
}

func (c *clientYAML) toRepository(tenantSlug string) *repository.Client {
	profile := strings.TrimSpace(c.AuthProfile)
	if profile == "" {
		profile = "spa"
	}

	return &repository.Client{
		TenantID:                 tenantSlug,
		ClientID:                 c.ClientID,
		Name:                     c.Name,
		Type:                     c.Type,
		AuthProfile:              profile,
		RedirectURIs:             c.RedirectURIs,
		AllowedOrigins:           c.AllowedOrigins,
		Providers:                c.Providers,
		Scopes:                   c.Scopes,
		SecretEnc:                c.SecretEnc,
		RequireEmailVerification: c.RequireEmailVerification,
		ResetPasswordURL:         c.ResetPasswordURL,
		VerifyEmailURL:           c.VerifyEmailURL,
		ClaimSchema:              c.ClaimSchema,
		ClaimMapping:             c.ClaimMapping,
		GrantTypes:               c.GrantTypes,
		AccessTokenTTL:           c.AccessTokenTTL,
		RefreshTokenTTL:          c.RefreshTokenTTL,
		IDTokenTTL:               c.IDTokenTTL,
		PostLogoutURIs:           c.PostLogoutURIs,
		Description:              c.Description,
	}
}

type scopesYAML struct {
	Scopes []scopeYAML `yaml:"scopes"`
}

type scopeYAML struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	DisplayName string   `yaml:"display_name,omitempty"`
	Claims      []string `yaml:"claims,omitempty"`
	DependsOn   string   `yaml:"depends_on,omitempty"`
	System      bool     `yaml:"system,omitempty"`
	CreatedAt   string   `yaml:"created_at,omitempty"`
	UpdatedAt   string   `yaml:"updated_at,omitempty"`
}
