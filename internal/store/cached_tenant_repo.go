// internal/store/cached_tenant_repo.go
// Decorador Read-Through Cache para TenantRepository.
package store

import (
	"context"
	"errors"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// cachedTenantRepo es un decorador Read-Through Cache para TenantRepository.
//
// Semántica:
//   - Lecturas: intenta primero el 'primary' (Global DB). Si falla por error de
//     conectividad (context deadline, DB down), usa el 'cache' (FS) como fallback.
//     ErrNotFound NO hace fallback — un tenant borrado de DB no debe aparecer via FS.
//   - Escrituras: SIEMPRE van al 'primary'. El 'cache' (FS) NO recibe escrituras.
//     El FS es caché de lectura, no de escritura. Las escrituras en DB son la fuente
//     de verdad; si fallan, se retorna error al caller.
//
// Por qué el FS no recibe writes:
//
//	En un entorno multi-nodo, escribir al FS local crearía divergencia entre nodos
//	(nodo A tiene el write en su FS local, nodo B no). La DB centralizada es el único
//	punto de sincronización. El FS es solo una copia local para sobrevivir cortes de DB.
type cachedTenantRepo struct {
	primary repository.TenantRepository // Global DB — fuente de verdad
	cache   repository.TenantRepository // FS — caché de lectura fallback
}

// NewCachedTenantRepo crea un decorador Read-Through Cache.
func NewCachedTenantRepo(primary, cache repository.TenantRepository) repository.TenantRepository {
	return &cachedTenantRepo{primary: primary, cache: cache}
}

func (r *cachedTenantRepo) GetBySlug(ctx context.Context, slug string) (*repository.Tenant, error) {
	t, err := r.primary.GetBySlug(ctx, slug)
	if err == nil {
		return t, nil
	}
	// Fallback a FS solo si el error es de conectividad — ErrNotFound NO hace fallback.
	// Un tenant borrado de DB no debe aparecer vía FS.
	if errors.Is(err, repository.ErrNotFound) {
		return nil, err
	}
	return r.cache.GetBySlug(ctx, slug)
}

func (r *cachedTenantRepo) GetByID(ctx context.Context, id string) (*repository.Tenant, error) {
	t, err := r.primary.GetByID(ctx, id)
	if err == nil {
		return t, nil
	}
	if errors.Is(err, repository.ErrNotFound) {
		return nil, err
	}
	return r.cache.GetByID(ctx, id)
}

func (r *cachedTenantRepo) List(ctx context.Context) ([]repository.Tenant, error) {
	tenants, err := r.primary.List(ctx)
	if err == nil {
		return tenants, nil
	}
	// En List, si DB está caída: retornar lista del FS (puede estar incompleta — aceptable)
	return r.cache.List(ctx)
}

// Create — escribe SOLO en primary (DB). El FS no recibe el write.
func (r *cachedTenantRepo) Create(ctx context.Context, tenant *repository.Tenant) error {
	return r.primary.Create(ctx, tenant)
}

// Update — escribe SOLO en primary (DB).
func (r *cachedTenantRepo) Update(ctx context.Context, tenant *repository.Tenant) error {
	return r.primary.Update(ctx, tenant)
}

// Delete — escribe SOLO en primary (DB).
func (r *cachedTenantRepo) Delete(ctx context.Context, slug string) error {
	return r.primary.Delete(ctx, slug)
}

// UpdateSettings — escribe SOLO en primary (DB).
func (r *cachedTenantRepo) UpdateSettings(ctx context.Context, slug string, settings *repository.TenantSettings) error {
	return r.primary.UpdateSettings(ctx, slug, settings)
}

// Verificación en compilación.
var _ repository.TenantRepository = (*cachedTenantRepo)(nil)
