package cache

import (
	"context"
	"sync"
	"time"
)

// memoryClient implementa Client usando un map en memoria.
// Útil para desarrollo y testing.
type memoryClient struct {
	prefix string
	data   map[string]memoryEntry
	mu     sync.RWMutex
	hits   int64
	misses int64
}

type memoryEntry struct {
	value     string
	expiresAt time.Time
	noExpire  bool
}

// NewMemory crea un cliente de cache en memoria.
func NewMemory(prefix string) *memoryClient {
	return &memoryClient{
		prefix: prefix,
		data:   make(map[string]memoryEntry),
	}
}

func (c *memoryClient) key(k string) string {
	if c.prefix == "" {
		return k
	}
	return c.prefix + ":" + k
}

func (c *memoryClient) Get(ctx context.Context, key string) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.data[c.key(key)]
	if !ok {
		c.misses++
		return "", ErrNotFound
	}

	// Verificar expiración
	if !entry.noExpire && time.Now().After(entry.expiresAt) {
		c.misses++
		return "", ErrNotFound
	}

	c.hits++
	return entry.value, nil
}

func (c *memoryClient) GetDel(ctx context.Context, key string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	k := c.key(key)
	entry, ok := c.data[k]
	if !ok {
		c.misses++
		return "", ErrNotFound
	}

	// Verificar expiración
	if !entry.noExpire && time.Now().After(entry.expiresAt) {
		delete(c.data, k)
		c.misses++
		return "", ErrNotFound
	}

	c.hits++
	delete(c.data, k)
	return entry.value, nil
}

func (c *memoryClient) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry := memoryEntry{
		value:    value,
		noExpire: ttl == 0,
	}
	if ttl > 0 {
		entry.expiresAt = time.Now().Add(ttl)
	}

	c.data[c.key(key)] = entry
	return nil
}

func (c *memoryClient) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, c.key(key))
	return nil
}

func (c *memoryClient) Exists(ctx context.Context, key string) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.data[c.key(key)]
	if !ok {
		return false, nil
	}

	// Verificar expiración
	if !entry.noExpire && time.Now().After(entry.expiresAt) {
		return false, nil
	}

	return true, nil
}

func (c *memoryClient) Ping(ctx context.Context) error {
	return nil
}

func (c *memoryClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = nil
	return nil
}

func (c *memoryClient) Stats(ctx context.Context) (Stats, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Contar solo keys no expiradas
	var count int64
	now := time.Now()
	for _, entry := range c.data {
		if entry.noExpire || now.Before(entry.expiresAt) {
			count++
		}
	}

	return Stats{
		Driver: "memory",
		Keys:   count,
		Hits:   c.hits,
		Misses: c.misses,
	}, nil
}

// Cleanup elimina entradas expiradas. Llamar periódicamente.
func (c *memoryClient) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for k, entry := range c.data {
		if !entry.noExpire && now.After(entry.expiresAt) {
			delete(c.data, k)
		}
	}
}
