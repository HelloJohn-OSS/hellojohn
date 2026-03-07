package adaptive

import "strings"

type ipChangeRule struct{}

// NewIPChangeRule returns the v1 IP change adaptive rule.
func NewIPChangeRule() Rule { return ipChangeRule{} }

func (ipChangeRule) Name() string { return "ip_change" }

func (ipChangeRule) Evaluate(ctx Context, _ Config) (bool, string) {
	current := strings.TrimSpace(ctx.CurrentIP)
	last := strings.TrimSpace(ctx.LastIP)
	if current == "" || last == "" {
		return false, ""
	}
	if current == last {
		return false, ""
	}
	return true, "client IP changed"
}
