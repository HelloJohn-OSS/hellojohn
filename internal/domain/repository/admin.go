package repository

import (
	"context"
	"time"
)

// TenantAccessEntry representa el acceso de un admin a un tenant específico.
type TenantAccessEntry struct {
	TenantSlug string `json:"tenant_slug" yaml:"tenant_slug"`
	Role       string `json:"role"        yaml:"role"` // "owner" | "member" | "readonly"
}

// AdminType representa el tipo de administrador
type AdminType string

const (
	AdminTypeGlobal AdminType = "global" // Admin del sistema completo
	AdminTypeTenant AdminType = "tenant" // Admin con acceso limitado a tenants específicos
)

// Admin representa un administrador del sistema
type Admin struct {
	ID           string    `json:"id"`            // UUID único del admin
	Email        string    `json:"email"`         // Email del admin (único)
	PasswordHash string    `json:"password_hash"` // Hash argon2id del password
	Name         string    `json:"name"`          // Nombre completo (opcional)
	Type         AdminType `json:"type"`          // Tipo de admin (global | tenant)

	// Para admins de tipo "tenant"
	// MIGRADO: TenantAccess reemplaza AssignedTenants; se mantiene AssignedTenants para compat YAML legacy.
	TenantAccess    []TenantAccessEntry `json:"tenant_access,omitempty"    yaml:"tenant_access,omitempty"`
	AssignedTenants []string            `json:"-"                           yaml:"assigned_tenants,omitempty"` // legacy yaml — leer en readAdmins() y migrar a TenantAccess

	// Metadata
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"` // Última vez que hizo login
	DisabledAt *time.Time `json:"disabled_at,omitempty"`  // Si está deshabilitado
	CreatedBy  *string    `json:"created_by,omitempty"`   // ID del admin que lo creó

	// Invite flow (omitempty — admins existentes no se rompen)
	Status          string     `yaml:"status,omitempty"           json:"status"` // "" / "pending" / "active"
	InviteTokenHash string     `yaml:"invite_token_hash,omitempty" json:"-"`     // SHA-256 del token; nunca exponer
	InviteExpiresAt *time.Time `yaml:"invite_expires_at,omitempty" json:"invite_expires_at,omitempty"`

	// Cloud-only fields (vacío en OSS — no breaking)
	EmailVerified  bool   `json:"email_verified"                    yaml:"email_verified"`
	SocialProvider string `json:"social_provider,omitempty"         yaml:"social_provider,omitempty"`
	// "google" | "github" | "microsoft" | "" (vacío = email/password)
	StripeCustomerID string `json:"-"                                 yaml:"-"` // nunca exponer en API
	Plan             string `json:"plan,omitempty"                    yaml:"plan,omitempty"`
	// "free" | "starter" | "pro" | "enterprise"
	OnboardingCompleted bool `json:"onboarding_completed" yaml:"onboarding_completed,omitempty"`
}

// AdminEmailVerification es el token de verificación de email (cloud).
type AdminEmailVerification struct {
	ID        string
	AdminID   string
	TokenHash string // SHA-256 del token raw
	ExpiresAt time.Time
	UsedAt    *time.Time
	CreatedAt time.Time
}

// GetTenantRole retorna el rol del admin para un tenant dado.
// Los admins globales siempre retornan "owner".
func (a *Admin) GetTenantRole(tenantSlug string) string {
	if a.Type == AdminTypeGlobal {
		return "owner"
	}
	for _, entry := range a.TenantAccess {
		if entry.TenantSlug == tenantSlug {
			return entry.Role
		}
	}
	return ""
}

// HasTenantAccess retorna true si el admin tiene acceso al tenant.
// Los admins globales siempre retornan true.
func (a *Admin) HasTenantAccess(tenantSlug string) bool {
	if a.Type == AdminTypeGlobal {
		return true
	}
	for _, entry := range a.TenantAccess {
		if entry.TenantSlug == tenantSlug {
			return true
		}
	}
	return false
}

// AdminRepository maneja la persistencia de administradores del sistema.
// Los admins se almacenan en el Control Plane (FileSystem).
//
// Ubicación: /data/admins/
//   - admins.yaml: Lista de todos los admins
//
// Estructura admins.yaml:
//
//	admins:
//	  - id: uuid
//	    email: admin@example.com
//	    password_hash: argon2id_hash
//	    name: John Doe
//	    type: global
//	    created_at: 2026-01-22T10:00:00Z
//	    updated_at: 2026-01-22T10:00:00Z
//	  - id: uuid2
//	    email: tenant-admin@example.com
//	    type: tenant
//	    assigned_tenants:
//	      - tenant-uuid-1
//	      - tenant-uuid-2
type AdminRepository interface {
	// ─── Read Operations ───

	// List retorna todos los admins del sistema.
	// Soporta filtrado por tipo (opcional).
	List(ctx context.Context, filter AdminFilter) ([]Admin, error)

	// GetByID busca un admin por su ID.
	// Retorna ErrNotFound si no existe.
	GetByID(ctx context.Context, id string) (*Admin, error)

	// GetByEmail busca un admin por su email.
	// Retorna ErrNotFound si no existe.
	GetByEmail(ctx context.Context, email string) (*Admin, error)

	// ─── Write Operations ───

	// Create crea un nuevo admin.
	// El email debe ser único.
	// Retorna ErrConflict si el email ya existe.
	Create(ctx context.Context, input CreateAdminInput) (*Admin, error)

	// Update actualiza un admin existente.
	// Solo se actualizan los campos no-nil en el input.
	Update(ctx context.Context, id string, input UpdateAdminInput) (*Admin, error)

	// Delete elimina un admin del sistema.
	// Retorna ErrNotFound si no existe.
	Delete(ctx context.Context, id string) error

	// ─── Auth Operations ───

	// CheckPassword verifica si un password es correcto para un admin.
	// Retorna true si coincide, false si no.
	CheckPassword(passwordHash, plainPassword string) bool

	// UpdateLastSeen actualiza el timestamp de último login.
	UpdateLastSeen(ctx context.Context, id string) error

	// ─── Tenant Assignment (solo para AdminTypeTenant) ───

	// AssignTenants asigna tenants a un admin de tipo tenant.
	// Reemplaza la lista completa de tenants asignados.
	AssignTenants(ctx context.Context, adminID string, tenantIDs []string) error

	// HasAccessToTenant verifica si un admin tiene acceso a un tenant específico.
	// Los admins globales siempre retornan true.
	// Los admins de tenant retornan true solo si el tenant está asignado.
	HasAccessToTenant(ctx context.Context, adminID, tenantID string) (bool, error)

	// ─── Invite Operations ───

	// SetInviteToken persiste el hash del token de invitación y su expiración.
	// Establece Status="pending" automáticamente.
	SetInviteToken(ctx context.Context, id, tokenHash string, expiresAt time.Time) error

	// GetByInviteTokenHash busca un admin por su token de invitación (comparando hash).
	// Retorna ErrNotFound si no existe o ya fue activado.
	GetByInviteTokenHash(ctx context.Context, tokenHash string) (*Admin, error)

	// ActivateWithPassword establece el password, borra el invite token y
	// cambia el status a "active". Operación atómica.
	ActivateWithPassword(ctx context.Context, id, passwordHash string) error

	// ─── Cloud Email Verification ───

	// CreateEmailVerification persiste un nuevo token de verificación.
	CreateEmailVerification(ctx context.Context, v AdminEmailVerification) error

	// GetEmailVerificationByHash busca una verificación por hash.
	// Retorna ErrNotFound si no existe.
	GetEmailVerificationByHash(ctx context.Context, hash string) (*AdminEmailVerification, error)

	// MarkEmailVerificationUsed marca la verificación como usada.
	MarkEmailVerificationUsed(ctx context.Context, id string) error

	// UpdateEmailVerified actualiza email_verified y opcionalmente status del admin.
	UpdateEmailVerified(ctx context.Context, adminID string, verified bool) error

	// UpdateSocialProvider actualiza los campos social_provider y plan.
	UpdateSocialProvider(ctx context.Context, adminID, provider, plan string) error

	// ─── Cloud Billing ───

	// UpdatePlan actualiza el campo plan del admin.
	UpdatePlan(ctx context.Context, adminID, plan string) error

	// SetOnboardingCompleted marca si el admin completó el wizard de onboarding.
	SetOnboardingCompleted(ctx context.Context, adminID string, completed bool) error

	// CountTenantsByAdmin cuenta los tenants a los que tiene acceso el admin.
	// Para admins globales, retorna el total de tenants del sistema.
	// Para billing: verifica límite de tenant_limit del plan.
	CountTenantsByAdmin(ctx context.Context, adminID string) (int, error)

	// CountAdminsByOwner cuenta los admins creados por el admin dado.
	// Para billing: verifica límite de admin_limit del plan.
	CountAdminsByOwner(ctx context.Context, adminID string) (int, error)

	// GetCurrentMAU retorna el Monthly Active Users del mes actual para el admin.
	// Para billing: verifica límite de mau_limit del plan.
	// Retorna 0 si el tracking de MAU no está disponible (fail-open).
	GetCurrentMAU(ctx context.Context, adminID string) (int, error)
}

// AdminFilter define filtros para listar admins
type AdminFilter struct {
	Type     *AdminType // Filtrar por tipo (nil = todos)
	Disabled *bool      // Filtrar por estado (nil = todos, true = solo disabled, false = solo activos)
	Limit    int        // Límite de resultados (0 = sin límite)
	Offset   int        // Offset para paginación
}

// CreateAdminInput define los datos para crear un admin
type CreateAdminInput struct {
	Email        string              // Requerido
	PasswordHash string              // Requerido si SendInvite=false; vacío si SendInvite=true
	Name         string              // Opcional
	Type         AdminType           // Requerido (global | tenant)
	TenantAccess []TenantAccessEntry // Opcional (solo para AdminTypeTenant)
	CreatedBy    *string             // Opcional (ID del admin que lo crea)
	// Invite flow
	Status          string // "pending" (invite) | "active" (direct)
	InviteTokenHash string // Pre-calculado por el caller — vacío si no hay invite
	InviteExpiresAt *time.Time
	// Cloud fields (opcionales — OSS no los usa)
	EmailVerified  bool
	SocialProvider string
	Plan           string // "" → default "free" en cloud
}

// UpdateAdminInput define los campos actualizables de un admin
type UpdateAdminInput struct {
	Email           *string              // Opcional
	PasswordHash    *string              // Opcional
	Name            *string              // Opcional
	TenantAccess    *[]TenantAccessEntry // Opcional (solo para AdminTypeTenant)
	DisabledAt      *time.Time           // Opcional (non-nil = deshabilitar con esta fecha)
	ClearDisabledAt bool                 // true = limpiar DisabledAt (habilitar admin)
	Status          *string              // Opcional: "pending" | "active"
	InviteTokenHash *string              // Opcional: vacío = limpiar token; no-nil = setear hash
	InviteExpiresAt **time.Time          // Opcional: pointer-to-pointer para distinguir "no tocar" de "limpiar"
	// Cloud fields
	EmailVerified  *bool
	SocialProvider *string
	Plan           *string
}

// ═══════════════════════════════════════════════════════════════════════════════
// Admin Refresh Tokens
// ═══════════════════════════════════════════════════════════════════════════════

// AdminRefreshToken representa un refresh token de admin persistido.
type AdminRefreshToken struct {
	TokenHash string    `json:"token_hash"` // SHA-256 hash del token
	AdminID   string    `json:"admin_id"`   // ID del admin propietario
	ExpiresAt time.Time `json:"expires_at"` // Fecha de expiración
	CreatedAt time.Time `json:"created_at"` // Fecha de creación
}

// AdminRefreshTokenRepository maneja la persistencia de refresh tokens de admin.
// Los refresh tokens se almacenan en el Control Plane (FileSystem).
//
// Ubicación: /data/admins/refresh_tokens.yaml
//
// Estructura refresh_tokens.yaml:
//
//	refresh_tokens:
//	  - token_hash: sha256_hash
//	    admin_id: uuid
//	    expires_at: 2026-02-22T10:00:00Z
//	    created_at: 2026-01-22T10:00:00Z
type AdminRefreshTokenRepository interface {
	// ─── Read Operations ───

	// GetByTokenHash busca un refresh token por su hash.
	// Retorna ErrNotFound si no existe.
	GetByTokenHash(ctx context.Context, tokenHash string) (*AdminRefreshToken, error)

	// ListByAdminID retorna todos los refresh tokens de un admin.
	ListByAdminID(ctx context.Context, adminID string) ([]AdminRefreshToken, error)

	// ─── Write Operations ───

	// Create crea un nuevo refresh token.
	// Retorna ErrConflict si el hash ya existe.
	Create(ctx context.Context, input CreateAdminRefreshTokenInput) error

	// Delete elimina un refresh token por su hash.
	// Retorna ErrNotFound si no existe.
	Delete(ctx context.Context, tokenHash string) error

	// DeleteByAdminID elimina todos los refresh tokens de un admin.
	// Útil cuando se deshabilita o elimina un admin.
	DeleteByAdminID(ctx context.Context, adminID string) (int, error)

	// DeleteExpired elimina todos los refresh tokens expirados.
	// Retorna el número de tokens eliminados.
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}

// CreateAdminRefreshTokenInput define los datos para crear un refresh token.
type CreateAdminRefreshTokenInput struct {
	AdminID   string    // Requerido
	TokenHash string    // Requerido (SHA-256 del token opaco)
	ExpiresAt time.Time // Requerido
}
