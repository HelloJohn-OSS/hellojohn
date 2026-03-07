package repository

import (
	"context"
	"strings"
	"time"
)

// Constantes de scope — taxonomía definitiva
//
// Scopes de API keys y sus capacidades:
//
//   - APIKeyScopeAdmin ("admin"): acceso completo a todos los endpoints admin. Úsalo
//     solo para automatización interna de confianza. Puede crear, modificar y eliminar
//     tenants, clients, usuarios y otras API keys.
//
//   - APIKeyScopeReadOnly ("readonly"): acceso de solo lectura (GET) a todos los
//     endpoints admin. Las mutaciones (POST/PUT/PATCH/DELETE) son rechazadas con 403.
//     Ideal para dashboards de monitoreo y pipelines de auditoría.
//
//   - APIKeyScopeCloud ("cloud"): acceso admin completo excepto las rutas listadas
//     en CloudScopeBlockedPaths (creación de API keys, gestión de cluster y rotación
//     de signing keys). Diseñado para el panel cloud de HelloJohn.
//
//   - "tenant:{slug}" (dinámico): restringe el acceso al tenant específico.
//     Usar strings.HasPrefix(scope, "tenant:") para detectar este scope.
const (
	APIKeyScopeAdmin    = "admin"
	APIKeyScopeReadOnly = "readonly"
	APIKeyScopeCloud    = "cloud"
	// "tenant:{slug}" es dinámico — usar strings.HasPrefix(scope, "tenant:")
)

// CloudScopeBlockedPaths son los paths bloqueados para keys con scope=cloud.
// Estos paths exponen operaciones destructivas o de seguridad que el cloud
// panel NO debe poder ejecutar remotamente.
// NOTA: las rutas de rotación de signing keys (/v2/admin/tenants/{id}/keys,
// /v2/admin/tenants/{id}/keys/rotate) son dinámicas y se verifican via
// HasSuffix en RequireAdminAuthOrAPIKey en lugar de listarse aquí.
var CloudScopeBlockedPaths = []string{
	"/v2/admin/api-keys", // creación/listado de API keys — podría crear nuevos accesos admin
	"/v2/admin/cluster",  // gestión de cluster — operación de infraestructura destructiva
}

// APIKey es la representación de una API key activa o revocada.
type APIKey struct {
	ID         string
	Name       string
	KeyPrefix  string // Primeros 14 chars del token raw (para identificación visual)
	KeyHash    string `json:"-"` // "sha256:{64 hex chars}" — NUNCA el token en claro; omitido de toda serialización JSON
	Scope      string // "admin" | "readonly" | "cloud" | "tenant:{slug}"
	CreatedBy  string // Email del admin que la creó
	CreatedAt  time.Time
	LastUsedAt *time.Time // nil hasta primer uso
	ExpiresAt  *time.Time // nil = no expira
	RevokedAt  *time.Time // nil = activa
}

// IsActive retorna true si la key no está revocada y no expiró.
func (k *APIKey) IsActive() bool {
	if k.RevokedAt != nil {
		return false
	}
	if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
		return false
	}
	return true
}

// TenantSlug extrae el slug si el scope es "tenant:{slug}". Retorna "" si no aplica.
func (k *APIKey) TenantSlug() string {
	if strings.HasPrefix(k.Scope, "tenant:") {
		return strings.TrimPrefix(k.Scope, "tenant:")
	}
	return ""
}

// ValidateScope verifica que el scope tenga un valor válido.
func ValidateScope(scope string) bool {
	switch scope {
	case APIKeyScopeAdmin, APIKeyScopeReadOnly, APIKeyScopeCloud:
		return true
	}
	if strings.HasPrefix(scope, "tenant:") {
		slug := strings.TrimPrefix(scope, "tenant:")
		return len(slug) > 0 && len(slug) <= 63
	}
	return false
}

// CreateAPIKeyInput es el input para crear una nueva key.
type CreateAPIKeyInput struct {
	Name      string
	Scope     string
	ExpiresIn *time.Duration // nil = no expira
	CreatedBy string         // Email del admin
}

// APIKeyRepository gestiona las API keys en el Control Plane.
// Implementación: FileSystem (fs adapter).
// PG/MySQL: noop (retornan nil, no se usan).
type APIKeyRepository interface {
	// Create persiste una nueva key. El token en claro nunca se almacena.
	Create(ctx context.Context, key APIKey) error

	// GetByHash busca una key por su hash SHA-256.
	// Retorna ErrNotFound si no existe.
	// CRÍTICO: usa comparación constant-time para prevenir timing attacks.
	GetByHash(ctx context.Context, hash string) (*APIKey, error)

	// List retorna todas las keys (activas y revocadas), sin el hash.
	List(ctx context.Context) ([]APIKey, error)

	// GetByID retorna una key por su UUID.
	GetByID(ctx context.Context, id string) (*APIKey, error)

	// Revoke marca la key como revocada (setea RevokedAt = now).
	// Idempotente: si ya está revocada, no falla.
	Revoke(ctx context.Context, id string) error

	// UpdateLastUsed actualiza last_used_at. Best-effort: ignorar errores.
	UpdateLastUsed(ctx context.Context, id string, at time.Time) error
}
