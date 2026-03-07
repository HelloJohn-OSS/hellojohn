package store

import (
	"context"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// ─── InfraStats ───

// TenantInfraStats contiene estadísticas de infraestructura de un tenant.
type TenantInfraStats struct {
	// Identificación
	TenantSlug string `json:"tenant_slug"`
	TenantID   string `json:"tenant_id"`
	Mode       string `json:"mode"`

	// Estado de DB
	HasDB   bool               `json:"has_db"`
	DBStats *DBConnectionStats `json:"db_stats,omitempty"`

	// Estado de Cache
	CacheEnabled bool       `json:"cache_enabled"`
	CacheStats   *CacheInfo `json:"cache_stats,omitempty"`

	// Metadata
	CollectedAt time.Time `json:"collected_at"`
}

// DBConnectionStats estadísticas de la conexión a BD.
type DBConnectionStats struct {
	Driver     string    `json:"driver"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	Healthy    bool      `json:"healthy"`
	Latency    string    `json:"latency,omitempty"`
}

// CacheInfo información básica del cache.
type CacheInfo struct {
	Driver     string `json:"driver"`
	Keys       int64  `json:"keys"`
	UsedMemory string `json:"used_memory,omitempty"`
	Hits       int64  `json:"hits"`
	Misses     int64  `json:"misses"`
}

// ─── CacheRepository Wrapper ───

// cacheRepoWrapper implementa repository.CacheRepository delegando a cache.Client.
type cacheRepoWrapper struct {
	client cache.Client
}

// NewCacheRepoWrapper crea un wrapper de cache.Client que implementa repository.CacheRepository.
func NewCacheRepoWrapper(client cache.Client) repository.CacheRepository {
	if client == nil {
		return nil
	}
	return &cacheRepoWrapper{client: client}
}

// ─── Core Operations ───

func (w *cacheRepoWrapper) Get(ctx context.Context, key string) ([]byte, bool) {
	val, err := w.client.Get(ctx, key)
	if err != nil {
		return nil, false
	}
	return []byte(val), true
}

func (w *cacheRepoWrapper) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return w.client.Set(ctx, key, string(value), ttl)
}

func (w *cacheRepoWrapper) Delete(ctx context.Context, key string) error {
	return w.client.Delete(ctx, key)
}

func (w *cacheRepoWrapper) Exists(ctx context.Context, key string) (bool, error) {
	return w.client.Exists(ctx, key)
}

// ─── Batch Operations (delegadas con loop simple) ───

func (w *cacheRepoWrapper) GetMulti(ctx context.Context, keys []string) (map[string][]byte, error) {
	result := make(map[string][]byte)
	for _, key := range keys {
		val, err := w.client.Get(ctx, key)
		if err == nil {
			result[key] = []byte(val)
		}
	}
	return result, nil
}

func (w *cacheRepoWrapper) SetMulti(ctx context.Context, values map[string][]byte, ttl time.Duration) error {
	for key, val := range values {
		if err := w.client.Set(ctx, key, string(val), ttl); err != nil {
			return err
		}
	}
	return nil
}

func (w *cacheRepoWrapper) DeleteMulti(ctx context.Context, keys []string) (int, error) {
	deleted := 0
	for _, key := range keys {
		if err := w.client.Delete(ctx, key); err == nil {
			deleted++
		}
	}
	return deleted, nil
}

// ─── Pattern Operations ───

func (w *cacheRepoWrapper) DeleteByPrefix(ctx context.Context, prefix string) (int, error) {
	// TODO: Implementar con SCAN para Redis, o iteración para memory cache
	// Por ahora retornamos 0 sin error (noop seguro)
	return 0, nil
}

// ─── Atomic Operations ───

func (w *cacheRepoWrapper) GetAndDelete(ctx context.Context, key string) ([]byte, bool, error) {
	val, err := w.client.Get(ctx, key)
	if err != nil {
		return nil, false, nil
	}
	_ = w.client.Delete(ctx, key)
	return []byte(val), true, nil
}

func (w *cacheRepoWrapper) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	exists, err := w.client.Exists(ctx, key)
	if err != nil {
		return false, err
	}
	if exists {
		return false, nil
	}
	return true, w.client.Set(ctx, key, string(value), ttl)
}

// ─── Health ───

func (w *cacheRepoWrapper) Ping(ctx context.Context) error {
	return w.client.Ping(ctx)
}

func (w *cacheRepoWrapper) Stats(ctx context.Context) (*repository.CacheStats, error) {
	stats, err := w.client.Stats(ctx)
	if err != nil {
		return nil, err
	}
	return &repository.CacheStats{
		Keys:   stats.Keys,
		Hits:   stats.Hits,
		Misses: stats.Misses,
	}, nil
}

func (w *cacheRepoWrapper) Close() error {
	return w.client.Close()
}
