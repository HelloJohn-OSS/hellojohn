package adaptive

import (
	"strings"
	"time"
)

const (
	DefaultFailureThreshold = 5
	DefaultStateTTL         = 30 * 24 * time.Hour // 720h
)

var defaultRules = []string{"ip_change", "ua_change", "failed_attempts"}

// Config controls adaptive MFA behavior.
type Config struct {
	Enabled          bool
	Rules            []string
	FailureThreshold int
	StateTTL         time.Duration
}

// Normalize applies safe defaults and canonical formatting.
func (c Config) Normalize() Config {
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = DefaultFailureThreshold
	}
	if c.StateTTL <= 0 {
		c.StateTTL = DefaultStateTTL
	}
	c.Rules = normalizeRules(c.Rules)
	return c
}

func normalizeRules(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	if len(out) == 0 {
		clone := make([]string, len(defaultRules))
		copy(clone, defaultRules)
		return clone
	}
	return out
}
