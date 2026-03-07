package session

import (
	"context"
	"time"

	cache "github.com/dropDatabas3/hellojohn/internal/cache"
)

// CacheAdapter adapts cache.Client to the session Cache interface.
type CacheAdapter struct {
	client cache.Client
}

// NewCacheAdapter creates a new CacheAdapter wrapping a cache.Client.
func NewCacheAdapter(client cache.Client) *CacheAdapter {
	return &CacheAdapter{client: client}
}

func (a *CacheAdapter) Get(key string) ([]byte, bool) {
	val, err := a.client.Get(context.Background(), key)
	if err != nil {
		return nil, false
	}
	return []byte(val), true
}

func (a *CacheAdapter) Set(key string, value []byte, ttl time.Duration) error {
	return a.client.Set(context.Background(), key, string(value), ttl)
}

func (a *CacheAdapter) Delete(key string) error {
	return a.client.Delete(context.Background(), key)
}
