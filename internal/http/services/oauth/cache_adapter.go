package oauth

import (
	"context"
	"time"

	cache "github.com/dropDatabas3/hellojohn/internal/cache"
)

// CacheAdapter adapts cache.Client (V2) to OAuth CacheClient interface.
type CacheAdapter struct {
	Client cache.Client
}

func NewCacheAdapter(client cache.Client) *CacheAdapter {
	return &CacheAdapter{Client: client}
}

func (a *CacheAdapter) Get(key string) ([]byte, bool) {
	val, err := a.Client.Get(context.Background(), key)
	if err != nil {
		return nil, false
	}
	return []byte(val), true
}

func (a *CacheAdapter) Set(key string, value []byte, ttl time.Duration) {
	_ = a.Client.Set(context.Background(), key, string(value), ttl)
}

func (a *CacheAdapter) Delete(key string) {
	_ = a.Client.Delete(context.Background(), key)
}
