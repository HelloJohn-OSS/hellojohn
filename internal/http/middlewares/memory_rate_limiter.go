package middlewares

import (
	"context"
	"sync"
	"time"
)

// MemoryRateLimiter implements RateLimiter using an in-memory fixed-window counter.
// It is safe for concurrent use and suitable for single-node deployments.
// For multi-node deployments, replace with a Redis-backed implementation.
type MemoryRateLimiter struct {
	limit   int64
	window  time.Duration
	mu      sync.Mutex
	entries map[string]*rlEntry
	stopCh  chan struct{}
}

type rlEntry struct {
	count     int64
	windowEnd time.Time
}

// NewMemoryRateLimiter creates an in-memory rate limiter.
//   - limit: maximum requests allowed per window per key.
//   - window: the sliding window duration (e.g. time.Minute).
func NewMemoryRateLimiter(limit int64, window time.Duration) *MemoryRateLimiter {
	rl := &MemoryRateLimiter{
		limit:   limit,
		window:  window,
		entries: make(map[string]*rlEntry),
		stopCh:  make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

// Allow checks whether the given key is within the rate limit for the current window.
// On limiter error it returns (Allowed=true, err) so the caller can still serve the request.
func (r *MemoryRateLimiter) Allow(_ context.Context, key string) (RateLimitResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	e, ok := r.entries[key]
	if !ok || now.After(e.windowEnd) {
		// Start a new window for this key.
		e = &rlEntry{count: 1, windowEnd: now.Add(r.window)}
		r.entries[key] = e
		return RateLimitResult{
			Allowed:     true,
			Remaining:   r.limit - 1,
			WindowTTL:   r.window,
			CurrentHits: 1,
		}, nil
	}

	e.count++
	allowed := e.count <= r.limit
	remaining := r.limit - e.count
	if remaining < 0 {
		remaining = 0
	}
	ttl := time.Until(e.windowEnd)

	res := RateLimitResult{
		Allowed:     allowed,
		Remaining:   remaining,
		WindowTTL:   ttl,
		CurrentHits: e.count,
	}
	if !allowed {
		res.RetryAfter = ttl
	}
	return res, nil
}

// Stop halts the background cleanup goroutine. Safe to call multiple times.
func (r *MemoryRateLimiter) Stop() {
	select {
	case <-r.stopCh:
		// already stopped
	default:
		close(r.stopCh)
	}
}

// cleanup removes expired window entries every 5 minutes to prevent unbounded memory growth.
func (r *MemoryRateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.mu.Lock()
			now := time.Now()
			for k, e := range r.entries {
				if now.After(e.windowEnd) {
					delete(r.entries, k)
				}
			}
			r.mu.Unlock()
		}
	}
}
