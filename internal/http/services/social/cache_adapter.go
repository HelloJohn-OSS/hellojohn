package social

import (
	"context"
	"time"

	cache "github.com/dropDatabas3/hellojohn/internal/cache"
)

// CacheAdapter adapts cache.Client (V2) to Social v2 CacheWriter interface.
type CacheAdapter struct {
	Client cache.Client
}

func NewCacheAdapter(client cache.Client) *CacheAdapter {
	return &CacheAdapter{Client: client}
}

func (a *CacheAdapter) Get(key string) ([]byte, bool) {
	// Social services don't pass context, so we use Background()
	val, err := a.Client.Get(context.Background(), key)
	if err != nil {
		return nil, false
	}
	return []byte(val), true
}

func (a *CacheAdapter) Delete(key string) error {
	return a.Client.Delete(context.Background(), key)
}

func (a *CacheAdapter) Set(key string, value []byte, ttl time.Duration) {
	_ = a.Client.Set(context.Background(), key, string(value), ttl)
}
