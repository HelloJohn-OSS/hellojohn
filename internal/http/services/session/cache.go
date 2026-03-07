package session

import "time"

// Cache abstracts session storage used by login/session-token flows.
type Cache interface {
	Get(key string) ([]byte, bool)
	Set(key string, value []byte, ttl time.Duration) error
	Delete(key string) error
}
