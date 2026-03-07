package rate

import (
	"context"
	"fmt"
	"sync"
	"time"

	rdb "github.com/redis/go-redis/v9"
)

// MultiRedisLimiter permite usar diferentes límites dinámicamente
// manteniendo el algoritmo fixed-window del RedisLimiter original
type MultiRedisLimiter struct {
	client *rdb.Client
	prefix string
	mu     sync.RWMutex
	// Cache de limiters por configuración para eficiencia
	limiters map[string]*RedisLimiter
}

func NewMultiRedisLimiter(client *rdb.Client, prefix string) *MultiRedisLimiter {
	if prefix == "" {
		prefix = "rl:"
	}
	return &MultiRedisLimiter{
		client:   client,
		prefix:   prefix,
		limiters: make(map[string]*RedisLimiter),
	}
}

// AllowWithLimits implementa la interfaz MultiLimiter
func (m *MultiRedisLimiter) AllowWithLimits(ctx context.Context, key string, limit int, window time.Duration) (Result, error) {
	// Generar clave única para esta configuración limit+window
	configKey := fmt.Sprintf("%d:%s", limit, window.String())

	// Buscar limiter cacheado
	m.mu.RLock()
	limiter, exists := m.limiters[configKey]
	m.mu.RUnlock()

	if !exists {
		// Crear nuevo limiter para esta configuración
		m.mu.Lock()
		// Double-check pattern para evitar race conditions
		if limiter, exists = m.limiters[configKey]; !exists {
			limiter = NewRedisLimiter(m.client, m.prefix, limit, window)
			m.limiters[configKey] = limiter
		}
		m.mu.Unlock()
	}

	// Usar el limiter específico para esta configuración
	return limiter.Allow(ctx, key)
}

// LimiterPoolAdapter convierte rate.Limiter existente a MultiLimiter
// para compatibilidad con código que ya usa la interfaz anterior
type LimiterPoolAdapter struct {
	multi *MultiRedisLimiter
}

func NewLimiterPoolAdapter(client *rdb.Client, prefix string) *LimiterPoolAdapter {
	return &LimiterPoolAdapter{
		multi: NewMultiRedisLimiter(client, prefix),
	}
}

func (l *LimiterPoolAdapter) AllowWithLimits(ctx context.Context, key string, limit int, window time.Duration) (Result, error) {
	return l.multi.AllowWithLimits(ctx, key, limit, window)
}

// Allow implementa la interfaz original rate.Limiter para compatibilidad hacia atrás
func (l *LimiterPoolAdapter) Allow(ctx context.Context, key string) (Result, error) {
	// Para la interfaz legacy, usar configuración por defecto
	// Este método solo se usa en middleware global, no en endpoints específicos
	return l.multi.AllowWithLimits(ctx, key, 60, time.Minute)
}

// NoopMultiLimiter cumple la interfaz y siempre permite
type NoopMultiLimiter struct{}

func (NoopMultiLimiter) AllowWithLimits(ctx context.Context, key string, limit int, window time.Duration) (Result, error) {
	return Result{
		Allowed:   true,
		Remaining: int64(limit),
		// WindowTTL / RetryAfter pueden quedar en cero; no usamos para bloquear
	}, nil
}
