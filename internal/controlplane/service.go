// Package controlplane proporciona la capa de servicio para operaciones del Control Plane.
// Esta capa encapsula lógica de negocio (validaciones, cifrado, orquestación)
// y delega la persistencia a Store V2.
//
// Arquitectura:
//
//	┌─────────────────────────────────────────────────────────────┐
//	│                       HANDLERS                              │
//	└───────────────────────────┬─────────────────────────────────┘
//	                            │
//	                            ▼
//	┌─────────────────────────────────────────────────────────────┐
//	│                   CONTROLPLANE SERVICE                      │
//	│  • Validaciones (ClientID, RedirectURI, IssuerMode)         │
//	│  • Cifrado de secrets (SMTP, DSN, ClientSecret)             │
//	│  • Reglas de negocio                                        │
//	└───────────────────────────┬─────────────────────────────────┘
//	                            │
//	                            ▼
//	┌─────────────────────────────────────────────────────────────┐
//	│                       STORE V2                              │
//	│  • CRUD puro (sin lógica de negocio)                        │
//	│  • Multi-driver (FS, PG, etc.)                              │
//	└─────────────────────────────────────────────────────────────┘
//
// ─── Service Interface ───
//
//	// ─── Tenants ───
//	ListTenants(ctx context.Context) ([]repository.Tenant, error)
//	GetTenant(ctx context.Context, tenantID string) (*repository.Tenant, error)
//	GetTenantByID(ctx context.Context, id string) (*repository.Tenant, error)
//	CreateTenant(ctx context.Context, name, slug string) (*repository.Tenant, error)
//	UpdateTenant(ctx context.Context, tenant *repository.Tenant) error
//	DeleteTenant(ctx context.Context, tenantID string) error
//	UpdateTenantSettings(ctx context.Context, tenantID string, settings *repository.TenantSettings) error
//
//	// ─── Clients ───
//	ListClients(ctx context.Context, tenantID string) ([]repository.Client, error)
//	GetClient(ctx context.Context, tenantID, clientID string) (*repository.Client, error)
//	CreateClient(ctx context.Context, tenantID string, input ClientInput) (*repository.Client, error)
//	UpdateClient(ctx context.Context, tenantID string, input ClientInput) (*repository.Client, error)
//	DeleteClient(ctx context.Context, tenantID, clientID string) error
//	DecryptClientSecret(ctx context.Context, tenantID, clientID string) (string, error)
//
//	// ─── Scopes ───
//	ListScopes(ctx context.Context, tenantID string) ([]repository.Scope, error)
//	CreateScope(ctx context.Context, tenantID, name, description string) (*repository.Scope, error)
//	DeleteScope(ctx context.Context, tenantID, name string) error
//
//	// ─── Validations ───
//	ValidateClientID(id string) bool
//	ValidateRedirectURI(uri string) bool
//	IsScopeAllowed(client *repository.Client, scope string) bool
package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/passwordpolicy"
	sec "github.com/dropDatabas3/hellojohn/internal/security/secretbox"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	"github.com/google/uuid"
)

// ─── Errors ───

var (
	ErrBadInput           = errors.New("control plane: bad input")
	ErrTenantNotFound     = errors.New("control plane: tenant not found")
	ErrClientNotFound     = errors.New("control plane: client not found")
	ErrScopeInUse         = errors.New("control plane: scope in use by client")
	ErrInvalidAuthProfile = errors.New("control plane: invalid auth profile")
)

// ─── Service Interface ───

// Service define las operaciones del Control Plane.
// Usa Store V2 internamente para persistencia.
type Service interface {
	// ─── Tenants ───
	ListTenants(ctx context.Context) ([]repository.Tenant, error)
	GetTenant(ctx context.Context, tenantID string) (*repository.Tenant, error)
	GetTenantByID(ctx context.Context, id string) (*repository.Tenant, error)
	CreateTenant(ctx context.Context, name, slug string, language string) (*repository.Tenant, error)
	UpdateTenant(ctx context.Context, tenant *repository.Tenant) error
	DeleteTenant(ctx context.Context, tenantID string) error
	UpdateTenantSettings(ctx context.Context, tenantID string, settings *repository.TenantSettings) error

	// ─── Clients ───
	ListClients(ctx context.Context, tenantID string) ([]repository.Client, error)
	GetClient(ctx context.Context, tenantID, clientID string) (*repository.Client, error)
	CreateClient(ctx context.Context, tenantID string, input ClientInput) (*repository.Client, error)
	UpdateClient(ctx context.Context, tenantID string, input ClientInput) (*repository.Client, error)
	DeleteClient(ctx context.Context, tenantID, clientID string) error
	DecryptClientSecret(ctx context.Context, tenantID, clientID string) (string, error)

	// ─── Scopes ───
	ListScopes(ctx context.Context, tenantID string) ([]repository.Scope, error)
	CreateScope(ctx context.Context, tenantID string, input repository.ScopeInput) (*repository.Scope, error)
	UpsertScope(ctx context.Context, tenantID string, input repository.ScopeInput) (*repository.Scope, error)
	DeleteScope(ctx context.Context, tenantID, name string) error

	// ─── Claims ───
	GetClaimsConfig(ctx context.Context, tenantID string) (*ClaimsConfig, error)
	ListCustomClaims(ctx context.Context, tenantID string) ([]repository.ClaimDefinition, error)
	CreateCustomClaim(ctx context.Context, tenantID string, input repository.ClaimInput) (*repository.ClaimDefinition, error)
	GetCustomClaim(ctx context.Context, tenantID, claimID string) (*repository.ClaimDefinition, error)
	UpdateCustomClaim(ctx context.Context, tenantID, claimID string, input repository.ClaimInput) (*repository.ClaimDefinition, error)
	DeleteCustomClaim(ctx context.Context, tenantID, claimID string) error
	ToggleStandardClaim(ctx context.Context, tenantID, claimName string, enabled bool) error
	GetClaimsSettings(ctx context.Context, tenantID string) (*repository.ClaimsSettings, error)
	UpdateClaimsSettings(ctx context.Context, tenantID string, input repository.ClaimsSettingsInput) (*repository.ClaimsSettings, error)
	GetScopeMappings(ctx context.Context, tenantID string) ([]repository.ScopeClaimMapping, error)

	// ─── Admins ───
	ListAdmins(ctx context.Context) ([]repository.Admin, error)
	GetAdmin(ctx context.Context, id string) (*repository.Admin, error)
	GetAdminByEmail(ctx context.Context, email string) (*repository.Admin, error)
	CreateAdmin(ctx context.Context, input CreateAdminInput) (*repository.Admin, error)
	UpdateAdmin(ctx context.Context, id string, input UpdateAdminInput) (*repository.Admin, error)
	DeleteAdmin(ctx context.Context, id string) error
	UpdateAdminPassword(ctx context.Context, id string, passwordHash string) error
	CheckAdminPassword(passwordHash, plainPassword string) bool
	DisableAdmin(ctx context.Context, id string) error
	EnableAdmin(ctx context.Context, id string) error
	SetAdminInvite(ctx context.Context, id, tokenHash string, expiresAt time.Time) error
	GetAdminByInviteToken(ctx context.Context, tokenHash string) (*repository.Admin, error)
	ActivateAdminInvite(ctx context.Context, id, passwordHash string) error

	// ─── Admin Refresh Tokens ───
	CreateAdminRefreshToken(ctx context.Context, input AdminRefreshTokenInput) error
	GetAdminRefreshToken(ctx context.Context, tokenHash string) (*AdminRefreshToken, error)
	DeleteAdminRefreshToken(ctx context.Context, tokenHash string) error
	CleanupExpiredAdminRefreshTokens(ctx context.Context) (int, error)

	// ─── Validations ───
	ValidateClientID(id string) bool
	ValidateRedirectURI(uri string) bool
	IsScopeAllowed(client *repository.Client, scope string) bool
	AllowedGrantsForProfile(profile string) []string
	ValidateGrant(profile, grant string) bool
}

// ClientInput contiene los datos para crear/actualizar un client.
type ClientInput struct {
	Name                     string
	ClientID                 string
	Type                     string // "public" | "confidential"
	AuthProfile              string
	RedirectURIs             []string
	AllowedOrigins           []string
	Providers                []string
	Scopes                   []string
	Secret                   string // Plain, se cifra al persistir
	RequireEmailVerification bool
	ResetPasswordURL         string
	VerifyEmailURL           string
	ClaimSchema              map[string]any
	ClaimMapping             map[string]any

	// Campos adicionales para OAuth2/OIDC avanzado
	GrantTypes      []string
	AccessTokenTTL  int
	RefreshTokenTTL int
	IDTokenTTL      int
	PostLogoutURIs  []string
	Description     string
}

// CreateAdminInput contiene los datos para crear un admin.
type CreateAdminInput struct {
	Email        string                       // Required
	PasswordHash string                       // Required if SendInvite=false; empty for invite flow
	Name         string                       // Optional
	Type         repository.AdminType         // Required (global | tenant)
	TenantAccess []repository.TenantAccessEntry // Optional (solo para AdminTypeTenant)
	CreatedBy    *string                      // Optional (ID del admin que lo crea)
	SendInvite   bool                         // true = crear admin pendiente y enviar email
}

// UpdateAdminInput contiene los datos para actualizar un admin.
type UpdateAdminInput struct {
	Email        *string                       // Optional
	Name         *string                       // Optional
	Type         *repository.AdminType         // Optional
	TenantAccess *[]repository.TenantAccessEntry // Optional
	DisabledAt   *time.Time                    // Optional (nil = enable, non-nil = disable)
}

// AdminRefreshTokenInput contiene los datos para crear un refresh token de admin.
type AdminRefreshTokenInput struct {
	AdminID   string    // ID del admin
	TokenHash string    // Hash SHA-256 del token
	ExpiresAt time.Time // Fecha de expiración
}

// AdminRefreshToken representa un refresh token de admin persistido.
type AdminRefreshToken struct {
	TokenHash string
	AdminID   string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// ─── Implementation ───

type service struct {
	store store.DataAccessLayer
}

// NewService crea un nuevo servicio de Control Plane.
func NewService(dal store.DataAccessLayer) Service {
	return &service{store: dal}
}

// ─── Tenants ───

func (s *service) ListTenants(ctx context.Context) ([]repository.Tenant, error) {
	return s.store.ConfigAccess().Tenants().List(ctx)
}

func (s *service) GetTenant(ctx context.Context, tenantID string) (*repository.Tenant, error) {
	tenant, err := s.store.ConfigAccess().Tenants().GetByID(ctx, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrTenantNotFound
		}
		return nil, err
	}
	return tenant, nil
}

func (s *service) GetTenantByID(ctx context.Context, id string) (*repository.Tenant, error) {
	tenant, err := s.store.ConfigAccess().Tenants().GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrTenantNotFound
		}
		return nil, err
	}
	return tenant, nil
}

func (s *service) CreateTenant(ctx context.Context, name, slug string, language string) (*repository.Tenant, error) {
	// Validaciones
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("%w: name required", ErrBadInput)
	}
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return nil, fmt.Errorf("%w: slug required", ErrBadInput)
	}
	if !isValidSlug(slug) {
		return nil, fmt.Errorf("%w: invalid slug format", ErrBadInput)
	}
	if language == "" {
		language = DefaultLanguage // Idioma por defecto
	}

	now := time.Now().UTC()
	tenant := &repository.Tenant{
		ID:        uuid.NewString(),
		Slug:      slug,
		Name:      name,
		Language:  language,
		CreatedAt: now,
		UpdatedAt: now,
		Settings: repository.TenantSettings{
			Mailing: &repository.MailingSettings{
				Templates: DefaultEmailTemplates(),
			},
			Security: func() *repository.SecurityPolicy {
				p := passwordpolicy.DefaultSimpleSecurityPolicy()
				return &p
			}(),
		},
	}

	if err := s.store.ConfigAccess().Tenants().Create(ctx, tenant); err != nil {
		return nil, err
	}
	return tenant, nil
}

func (s *service) UpdateTenant(ctx context.Context, tenant *repository.Tenant) error {
	tenant.UpdatedAt = time.Now().UTC()
	return s.store.ConfigAccess().Tenants().Update(ctx, tenant)
}

func (s *service) DeleteTenant(ctx context.Context, tenantID string) error {
	return s.store.ConfigAccess().Tenants().Delete(ctx, tenantID)
}

func (s *service) UpdateTenantSettings(ctx context.Context, tenantID string, settings *repository.TenantSettings) (retErr error) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[CRITICAL] panic in UpdateTenantSettings: %v\n%s", rec, debug.Stack())
			retErr = fmt.Errorf("UpdateTenantSettings: internal error (panic recovered)")
		}
	}()

	// Cifrar campos sensibles
	if settings.SMTP != nil && settings.SMTP.Password != "" {
		enc, err := sec.Encrypt(settings.SMTP.Password)
		if err != nil {
			return fmt.Errorf("encrypt SMTP password: %w", err)
		}
		settings.SMTP.PasswordEnc = enc
		settings.SMTP.Password = "" // Limpiar plain
	}

	if settings.UserDB != nil && settings.UserDB.DSN != "" {
		enc, err := sec.Encrypt(settings.UserDB.DSN)
		if err != nil {
			return fmt.Errorf("encrypt UserDB DSN: %w", err)
		}
		settings.UserDB.DSNEnc = enc
		settings.UserDB.DSN = "" // Limpiar plain
	}

	// Cifrar el DSN de bloqueo de migración (si está presente) para que no
	// quede en texto plano en tenant.yaml durante el proceso de migración.
	if settings.MigratingToDSN != "" {
		enc, err := sec.Encrypt(settings.MigratingToDSN)
		if err != nil {
			return fmt.Errorf("encrypt MigratingToDSN: %w", err)
		}
		settings.MigratingToDSN = enc
	}

	if settings.Cache != nil && settings.Cache.Password != "" {
		enc, err := sec.Encrypt(settings.Cache.Password)
		if err != nil {
			return fmt.Errorf("encrypt Cache password: %w", err)
		}
		settings.Cache.PassEnc = enc
		settings.Cache.Password = "" // Limpiar plain
	}

	err := s.store.ConfigAccess().Tenants().UpdateSettings(ctx, tenantID, settings)
	if err == nil {
		s.store.InvalidateTenantCache(tenantID)
	}
	return err
}

// ─── Clients ───

func (s *service) ListClients(ctx context.Context, tenantID string) ([]repository.Client, error) {
	return s.store.ConfigAccess().Clients(tenantID).List(ctx, "")
}

func (s *service) GetClient(ctx context.Context, tenantID, clientID string) (*repository.Client, error) {
	client, err := s.store.ConfigAccess().Clients(tenantID).Get(ctx, clientID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}
	return client, nil
}

func (s *service) CreateClient(ctx context.Context, tenantID string, input ClientInput) (*repository.Client, error) {
	// Validaciones
	if !s.ValidateClientID(input.ClientID) {
		return nil, fmt.Errorf("%w: invalid clientId", ErrBadInput)
	}
	if strings.TrimSpace(input.Name) == "" {
		return nil, fmt.Errorf("%w: name required", ErrBadInput)
	}
	if input.Type != "public" && input.Type != "confidential" {
		return nil, fmt.Errorf("%w: invalid client type", ErrBadInput)
	}

	profile, err := NormalizeAuthProfile(input.AuthProfile)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAuthProfile, err)
	}
	input.AuthProfile = profile
	input.GrantTypes = CoerceGrantTypesForProfile(profile, input.GrantTypes)

	// RedirectURIs solo es required si no es M2M (client_credentials only)
	isM2M := input.AuthProfile == AuthProfileM2M
	if len(input.RedirectURIs) == 0 && !isM2M {
		return nil, fmt.Errorf("%w: redirectUris required", ErrBadInput)
	}

	redirectURIs := make([]string, 0, len(input.RedirectURIs))
	for _, uri := range input.RedirectURIs {
		canonicalURI, ok := canonicalizeRedirectURI(uri)
		if !ok {
			return nil, fmt.Errorf("%w: invalid redirect uri: %s", ErrBadInput, uri)
		}
		redirectURIs = append(redirectURIs, canonicalURI)
	}

	// Cifrar secret para confidential clients
	var secretEnc string
	var plainSecret string
	if input.Type == "confidential" {
		// Si no se proporcionó secret, generar uno automáticamente
		if input.Secret == "" {
			// Generate a secure random secret (64 bytes = 512 bits)
			generated, err := tokens.GenerateOpaqueToken(64)
			if err != nil {
				return nil, fmt.Errorf("generate client secret: %w", err)
			}
			plainSecret = generated
		} else {
			plainSecret = input.Secret
		}

		enc, err := sec.Encrypt(plainSecret)
		if err != nil {
			return nil, fmt.Errorf("encrypt client secret: %w", err)
		}
		secretEnc = enc
	}

	repoInput := repository.ClientInput{
		Name:                     input.Name,
		ClientID:                 input.ClientID,
		Type:                     input.Type,
		AuthProfile:              input.AuthProfile,
		RedirectURIs:             uniqueStrings(redirectURIs),
		AllowedOrigins:           uniqueStrings(input.AllowedOrigins),
		Providers:                uniqueStrings(input.Providers),
		Scopes:                   uniqueStrings(input.Scopes),
		Secret:                   secretEnc, // Ya cifrado
		RequireEmailVerification: input.RequireEmailVerification,
		ResetPasswordURL:         input.ResetPasswordURL,
		VerifyEmailURL:           input.VerifyEmailURL,
		ClaimSchema:              input.ClaimSchema,
		ClaimMapping:             input.ClaimMapping,
		// Campos adicionales OAuth2/OIDC
		GrantTypes:      uniqueStrings(input.GrantTypes),
		AccessTokenTTL:  input.AccessTokenTTL,
		RefreshTokenTTL: input.RefreshTokenTTL,
		IDTokenTTL:      input.IDTokenTTL,
		PostLogoutURIs:  uniqueStrings(input.PostLogoutURIs),
		Description:     input.Description,
	}

	client, err := s.store.ConfigAccess().Clients(tenantID).Create(ctx, repoInput)
	if err != nil {
		return nil, err
	}

	// Si generamos el secret automáticamente, devolverlo en texto plano (única vez)
	// PlainSecret nunca se persiste (yaml:"-" json:"-" en el struct).
	if plainSecret != "" {
		client.PlainSecret = plainSecret
	}

	return client, nil
}

func (s *service) UpdateClient(ctx context.Context, tenantID string, input ClientInput) (*repository.Client, error) {
	// Validaciones similares a Create
	if !s.ValidateClientID(input.ClientID) {
		return nil, fmt.Errorf("%w: invalid clientId", ErrBadInput)
	}
	current, err := s.store.ConfigAccess().Clients(tenantID).Get(ctx, input.ClientID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrClientNotFound
		}
		return nil, err
	}

	if strings.TrimSpace(input.AuthProfile) == "" {
		input.AuthProfile = current.AuthProfile
	}
	// Inherit name and type from current when not provided
	if strings.TrimSpace(input.Name) == "" {
		input.Name = current.Name
	}
	if strings.TrimSpace(input.Type) == "" {
		input.Type = current.Type
	}
	profile, err := NormalizeAuthProfile(input.AuthProfile)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidAuthProfile, err)
	}
	input.AuthProfile = profile
	input.GrantTypes = CoerceGrantTypesForProfile(profile, input.GrantTypes)

	isM2M := input.AuthProfile == AuthProfileM2M
	if len(input.RedirectURIs) == 0 && !isM2M {
		// Fall back to current redirect URIs when not provided in update
		input.RedirectURIs = current.RedirectURIs
	}
	if len(input.RedirectURIs) == 0 && !isM2M {
		return nil, fmt.Errorf("%w: redirectUris required", ErrBadInput)
	}
	redirectURIs := make([]string, 0, len(input.RedirectURIs))
	for _, uri := range input.RedirectURIs {
		canonicalURI, ok := canonicalizeRedirectURI(uri)
		if !ok {
			return nil, fmt.Errorf("%w: invalid redirect uri: %s", ErrBadInput, uri)
		}
		redirectURIs = append(redirectURIs, canonicalURI)
	}

	// Cifrar secret si viene nuevo
	var secretEnc string
	if input.Type == "confidential" && input.Secret != "" {
		enc, err := sec.Encrypt(input.Secret)
		if err != nil {
			return nil, fmt.Errorf("encrypt client secret: %w", err)
		}
		secretEnc = enc
	}

	repoInput := repository.ClientInput{
		Name:                     input.Name,
		ClientID:                 input.ClientID,
		Type:                     input.Type,
		AuthProfile:              input.AuthProfile,
		RedirectURIs:             uniqueStrings(redirectURIs),
		AllowedOrigins:           uniqueStrings(input.AllowedOrigins),
		Providers:                uniqueStrings(input.Providers),
		Scopes:                   uniqueStrings(input.Scopes),
		Secret:                   secretEnc,
		RequireEmailVerification: input.RequireEmailVerification,
		ResetPasswordURL:         input.ResetPasswordURL,
		VerifyEmailURL:           input.VerifyEmailURL,
		ClaimSchema:              input.ClaimSchema,
		ClaimMapping:             input.ClaimMapping,
		// Campos adicionales OAuth2/OIDC
		GrantTypes:      uniqueStrings(input.GrantTypes),
		AccessTokenTTL:  input.AccessTokenTTL,
		RefreshTokenTTL: input.RefreshTokenTTL,
		IDTokenTTL:      input.IDTokenTTL,
		PostLogoutURIs:  uniqueStrings(input.PostLogoutURIs),
		Description:     input.Description,
	}

	return s.store.ConfigAccess().Clients(tenantID).Update(ctx, repoInput)
}

func (s *service) DeleteClient(ctx context.Context, tenantID, clientID string) error {
	return s.store.ConfigAccess().Clients(tenantID).Delete(ctx, clientID)
}

func (s *service) DecryptClientSecret(ctx context.Context, tenantID, clientID string) (string, error) {
	client, err := s.GetClient(ctx, tenantID, clientID)
	if err != nil {
		return "", err
	}
	if client.SecretEnc == "" {
		return "", nil
	}
	return sec.Decrypt(client.SecretEnc)
}

// ─── Scopes ───

func (s *service) ListScopes(ctx context.Context, tenantID string) ([]repository.Scope, error) {
	return s.store.ConfigAccess().Scopes(tenantID).List(ctx)
}

func (s *service) CreateScope(ctx context.Context, tenantID string, input repository.ScopeInput) (*repository.Scope, error) {
	if strings.TrimSpace(input.Name) == "" {
		return nil, fmt.Errorf("%w: scope name required", ErrBadInput)
	}
	return s.store.ConfigAccess().Scopes(tenantID).Create(ctx, input)
}

func (s *service) UpsertScope(ctx context.Context, tenantID string, input repository.ScopeInput) (*repository.Scope, error) {
	if strings.TrimSpace(input.Name) == "" {
		return nil, fmt.Errorf("%w: scope name required", ErrBadInput)
	}
	return s.store.ConfigAccess().Scopes(tenantID).Upsert(ctx, input)
}

func (s *service) DeleteScope(ctx context.Context, tenantID, name string) error {
	// Verificar que no esté en uso por algún client
	clients, err := s.ListClients(ctx, tenantID)
	if err != nil {
		return err
	}
	for _, c := range clients {
		for _, sc := range c.Scopes {
			if sc == name {
				return ErrScopeInUse
			}
		}
	}

	// Verificar que no sea requerido por otros scopes (depends_on)
	scopes, err := s.ListScopes(ctx, tenantID)
	if err != nil {
		return err
	}
	for _, scope := range scopes {
		if scope.DependsOn == name {
			return fmt.Errorf("%w: scope %s is required by %s", ErrScopeInUse, name, scope.Name)
		}
	}

	return s.store.ConfigAccess().Scopes(tenantID).Delete(ctx, name)
}

// ─── Claims ───

// ClaimsConfig representa la configuración completa de claims de un tenant.
type ClaimsConfig struct {
	StandardClaims []repository.StandardClaimConfig
	CustomClaims   []repository.ClaimDefinition
	Settings       *repository.ClaimsSettings
}

func (s *service) GetClaimsConfig(ctx context.Context, tenantID string) (*ClaimsConfig, error) {
	claimRepo := s.store.ConfigAccess().Claims(tenantID)

	standard, err := claimRepo.GetStandardClaimsConfig(ctx)
	if err != nil {
		return nil, err
	}

	custom, err := claimRepo.List(ctx)
	if err != nil {
		return nil, err
	}

	settings, err := claimRepo.GetSettings(ctx)
	if err != nil {
		return nil, err
	}

	return &ClaimsConfig{
		StandardClaims: standard,
		CustomClaims:   custom,
		Settings:       settings,
	}, nil
}

func (s *service) ListCustomClaims(ctx context.Context, tenantID string) ([]repository.ClaimDefinition, error) {
	return s.store.ConfigAccess().Claims(tenantID).List(ctx)
}

func (s *service) CreateCustomClaim(ctx context.Context, tenantID string, input repository.ClaimInput) (*repository.ClaimDefinition, error) {
	if strings.TrimSpace(input.Name) == "" {
		return nil, fmt.Errorf("%w: claim name required", ErrBadInput)
	}
	return s.store.ConfigAccess().Claims(tenantID).Create(ctx, input)
}

func (s *service) GetCustomClaim(ctx context.Context, tenantID, claimID string) (*repository.ClaimDefinition, error) {
	return s.store.ConfigAccess().Claims(tenantID).Get(ctx, claimID)
}

func (s *service) UpdateCustomClaim(ctx context.Context, tenantID, claimID string, input repository.ClaimInput) (*repository.ClaimDefinition, error) {
	return s.store.ConfigAccess().Claims(tenantID).Update(ctx, claimID, input)
}

func (s *service) DeleteCustomClaim(ctx context.Context, tenantID, claimID string) error {
	return s.store.ConfigAccess().Claims(tenantID).Delete(ctx, claimID)
}

func (s *service) ToggleStandardClaim(ctx context.Context, tenantID, claimName string, enabled bool) error {
	return s.store.ConfigAccess().Claims(tenantID).SetStandardClaimEnabled(ctx, claimName, enabled)
}

func (s *service) GetClaimsSettings(ctx context.Context, tenantID string) (*repository.ClaimsSettings, error) {
	return s.store.ConfigAccess().Claims(tenantID).GetSettings(ctx)
}

func (s *service) UpdateClaimsSettings(ctx context.Context, tenantID string, input repository.ClaimsSettingsInput) (*repository.ClaimsSettings, error) {
	return s.store.ConfigAccess().Claims(tenantID).UpdateSettings(ctx, input)
}

func (s *service) GetScopeMappings(ctx context.Context, tenantID string) ([]repository.ScopeClaimMapping, error) {
	// Build mappings from scopes that have claims
	scopes, err := s.ListScopes(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	var mappings []repository.ScopeClaimMapping
	for _, scope := range scopes {
		if len(scope.Claims) > 0 {
			mappings = append(mappings, repository.ScopeClaimMapping{
				Scope:  scope.Name,
				Claims: scope.Claims,
			})
		}
	}
	return mappings, nil
}

// ─── Validations ───

var reClientID = regexp.MustCompile(`^[a-z0-9\-_]+$`)

func (s *service) ValidateClientID(id string) bool {
	id = strings.TrimSpace(id)
	return len(id) >= 3 && len(id) <= 64 && reClientID.MatchString(id)
}

func (s *service) ValidateRedirectURI(uri string) bool {
	_, ok := canonicalizeRedirectURI(uri)
	return ok
}

func (s *service) IsScopeAllowed(client *repository.Client, scope string) bool {
	scope = strings.TrimSpace(scope)
	for _, s := range client.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func (s *service) AllowedGrantsForProfile(profile string) []string {
	return AllowedGrantsForProfile(profile)
}

func (s *service) ValidateGrant(profile, grant string) bool {
	return ValidateGrant(profile, grant)
}

// ─── Helpers ───

func isValidSlug(s string) bool {
	return regexp.MustCompile(`^[a-z0-9\-]+$`).MatchString(s)
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func canonicalizeRedirectURI(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if strings.Contains(raw, "*") {
		return "", false
	}

	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return "", false
	}
	if u.Fragment != "" {
		return "", false
	}

	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if scheme != "https" {
		if scheme != "http" || !(host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]" || strings.HasPrefix(host, "127.")) {
			return "", false
		}
	}

	u.Scheme = scheme
	u.Host = strings.ToLower(u.Host)
	if u.Path == "" {
		u.Path = "/"
	}

	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		u.Host = u.Hostname()
	}
	u.Fragment = ""
	return u.String(), true
}
