package redis

import (
	"context"
	"time"

	rdb "github.com/redis/go-redis/v9"
)

type Cache struct {
	c      *rdb.Client
	prefix string
}

func New(addr string, db int, prefix string) (*Cache, error) {
	cli := rdb.NewClient(&rdb.Options{Addr: addr, DB: db})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := cli.Ping(ctx).Err(); err != nil {
		return nil, err
	}
	return &Cache{c: cli, prefix: prefix}, nil
}

func (r *Cache) k(key string) string {
	if r.prefix != "" {
		return r.prefix + key
	}
	return key
}

func (r *Cache) Get(key string) ([]byte, bool) {
	b, err := r.c.Get(context.Background(), r.k(key)).Bytes()
	if err != nil {
		return nil, false
	}
	return b, true
}

func (r *Cache) Set(key string, v []byte, ttl time.Duration) {
	_ = r.c.Set(context.Background(), r.k(key), v, ttl).Err()
}

func (r *Cache) Delete(key string) {
	_ = r.c.Del(context.Background(), r.k(key)).Err()
}
