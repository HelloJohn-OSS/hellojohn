package adaptive

import "strings"

type uaChangeRule struct{}

// NewUAChangeRule returns the v1 User-Agent change adaptive rule.
func NewUAChangeRule() Rule { return uaChangeRule{} }

func (uaChangeRule) Name() string { return "ua_change" }

func (uaChangeRule) Evaluate(ctx Context, _ Config) (bool, string) {
	current := strings.TrimSpace(ctx.CurrentUA)
	last := strings.TrimSpace(ctx.LastUA)
	if current == "" || last == "" {
		return false, ""
	}
	if current == last {
		return false, ""
	}
	return true, "user agent changed"
}
