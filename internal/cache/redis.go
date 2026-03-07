package cache

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisClient implementa Client usando Redis.
type redisClient struct {
	client *redis.Client
	prefix string
}

// NewRedis crea un cliente de cache Redis.
func NewRedis(cfg Config) (*redisClient, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	if cfg.Port == 0 {
		addr = cfg.Host + ":6379"
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	// Verificar conexión
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("cache: redis ping failed: %w", err)
	}

	return &redisClient{
		client: rdb,
		prefix: cfg.Prefix,
	}, nil
}

func (c *redisClient) key(k string) string {
	if c.prefix == "" {
		return k
	}
	return c.prefix + ":" + k
}

func (c *redisClient) Get(ctx context.Context, key string) (string, error) {
	val, err := c.client.Get(ctx, c.key(key)).Result()
	if err == redis.Nil {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return val, nil
}

func (c *redisClient) GetDel(ctx context.Context, key string) (string, error) {
	val, err := c.client.GetDel(ctx, c.key(key)).Result()
	if err == redis.Nil {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	return val, nil
}

func (c *redisClient) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return c.client.Set(ctx, c.key(key), value, ttl).Err()
}

func (c *redisClient) Delete(ctx context.Context, key string) error {
	return c.client.Del(ctx, c.key(key)).Err()
}

func (c *redisClient) Exists(ctx context.Context, key string) (bool, error) {
	n, err := c.client.Exists(ctx, c.key(key)).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (c *redisClient) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

func (c *redisClient) Close() error {
	return c.client.Close()
}

func (c *redisClient) Stats(ctx context.Context) (Stats, error) {
	// Info memory
	info, err := c.client.Info(ctx, "memory").Result()
	if err != nil {
		return Stats{}, err
	}

	// Parse used_memory_human
	var usedMemory string
	for _, line := range strings.Split(info, "\r\n") {
		if strings.HasPrefix(line, "used_memory_human:") {
			usedMemory = strings.TrimPrefix(line, "used_memory_human:")
			break
		}
	}

	// DB Size (keys in current DB)
	keys, err := c.client.DBSize(ctx).Result()
	if err != nil {
		return Stats{}, err
	}

	// Stats de hits/misses
	statsInfo, _ := c.client.Info(ctx, "stats").Result()
	var hits, misses int64
	for _, line := range strings.Split(statsInfo, "\r\n") {
		if strings.HasPrefix(line, "keyspace_hits:") {
			fmt.Sscanf(strings.TrimPrefix(line, "keyspace_hits:"), "%d", &hits)
		}
		if strings.HasPrefix(line, "keyspace_misses:") {
			fmt.Sscanf(strings.TrimPrefix(line, "keyspace_misses:"), "%d", &misses)
		}
	}

	return Stats{
		Driver:     "redis",
		Keys:       keys,
		UsedMemory: usedMemory,
		Hits:       hits,
		Misses:     misses,
	}, nil
}
