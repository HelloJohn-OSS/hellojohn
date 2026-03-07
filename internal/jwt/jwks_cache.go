package jwt

import (
	"encoding/json"
	"sync"
	"time"
)

type jwksCacheEntry struct {
	data json.RawMessage
	exp  time.Time
}

// JWKSCache caches JWKS JSON per tenant for a short TTL.
type JWKSCache struct {
	mu   sync.RWMutex
	ttl  time.Duration
	load func(tenant string) (json.RawMessage, error)

	items map[string]jwksCacheEntry // tenant -> entry
}

func NewJWKSCache(ttl time.Duration, loader func(string) (json.RawMessage, error)) *JWKSCache {
	return &JWKSCache{
		ttl:   ttl,
		load:  loader,
		items: make(map[string]jwksCacheEntry),
	}
}

func (c *JWKSCache) Get(tenant string) (json.RawMessage, error) {
	key := tenant
	if key == "" {
		key = "global"
	}
	now := time.Now()

	c.mu.RLock()
	if e, ok := c.items[key]; ok && now.Before(e.exp) {
		c.mu.RUnlock()
		return e.data, nil
	}
	c.mu.RUnlock()

	data, err := c.load(tenant)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.items[key] = jwksCacheEntry{data: data, exp: now.Add(c.ttl)}
	c.mu.Unlock()
	return data, nil
}

// Invalidate removes the cached JWKS for a tenant (or global if tenant is empty).
func (c *JWKSCache) Invalidate(tenant string) {
	key := tenant
	if key == "" {
		key = "global"
	}
	c.mu.Lock()
	delete(c.items, key)
	c.mu.Unlock()
}
