package rate

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	rdb "github.com/redis/go-redis/v9"
)

type Result struct {
	Allowed     bool
	Remaining   int64
	RetryAfter  time.Duration
	WindowTTL   time.Duration
	CurrentHits int64
}

type Limiter interface {
	Allow(ctx context.Context, key string) (Result, error)
}

// RedisLimiter: fixed window sencillo (INCR + EXPIRE)
type RedisLimiter struct {
	Client *rdb.Client
	Prefix string
	Max    int64
	Window time.Duration
}

func NewRedisLimiter(client *rdb.Client, prefix string, max int, window time.Duration) *RedisLimiter {
	if prefix == "" {
		prefix = "rl:"
	}
	return &RedisLimiter{
		Client: client,
		Prefix: prefix,
		Max:    int64(max),
		Window: window,
	}
}

func (l *RedisLimiter) Allow(ctx context.Context, key string) (Result, error) {
	now := time.Now().UTC()
	winStart := now.Truncate(l.Window)
	redisKey := fmt.Sprintf("%s%s:%d", l.Prefix, strings.ReplaceAll(key, " ", "_"), winStart.Unix())

	pipe := l.Client.TxPipeline()
	incr := pipe.Incr(ctx, redisKey)
	ttl := pipe.TTL(ctx, redisKey)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return Result{}, err
	}

	// set expiry on first hit
	if incr.Val() == 1 {
		_ = l.Client.Expire(ctx, redisKey, l.Window).Err()
		ttl = l.Client.TTL(ctx, redisKey)
	}

	hits := incr.Val()
	allowed := hits <= l.Max
	remaining := l.Max - hits
	if remaining < 0 {
		remaining = 0
	}

	res := Result{
		Allowed:     allowed,
		Remaining:   remaining,
		CurrentHits: hits,
		WindowTTL:   ttl.Val(),
	}
	if !allowed {
		// Retry after: resto de la ventana
		res.RetryAfter = ttl.Val()
		if res.RetryAfter < 0 {
			res.RetryAfter = time.Duration(math.Ceil(l.Window.Seconds())) * time.Second
		}
	}
	return res, nil
}
