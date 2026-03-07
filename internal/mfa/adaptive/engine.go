package adaptive

import (
	"strings"
	"time"
)

// Rule evaluates adaptive context and decides if MFA must be required.
type Rule interface {
	Name() string
	Evaluate(ctx Context, cfg Config) (triggered bool, reason string)
}

// Result is the adaptive evaluation output.
type Result struct {
	RequireMFA bool
	Rule       string
	Reason     string
}

// Engine orchestrates adaptive rule evaluation.
type Engine struct {
	rules map[string]Rule
}

// NewEngine creates an engine with built-in v1 rules registered.
func NewEngine(extra ...Rule) *Engine {
	e := &Engine{rules: make(map[string]Rule, 8)}
	e.Register(NewIPChangeRule())
	e.Register(NewUAChangeRule())
	e.Register(NewFailedAttemptsRule())
	for _, rule := range extra {
		e.Register(rule)
	}
	return e
}

// Register adds or overrides a rule by name.
func (e *Engine) Register(rule Rule) {
	if e == nil || rule == nil {
		return
	}
	name := strings.ToLower(strings.TrimSpace(rule.Name()))
	if name == "" {
		return
	}
	e.rules[name] = rule
}

// Evaluate runs configured rules in order and returns on first match.
func (e *Engine) Evaluate(ctx Context, cfg Config) Result {
	if e == nil {
		return Result{}
	}
	cfg = cfg.Normalize()
	if !cfg.Enabled || len(cfg.Rules) == 0 {
		return Result{}
	}
	if ctx.Now.IsZero() {
		ctx.Now = time.Now().UTC()
	}
	for _, configuredName := range cfg.Rules {
		name := strings.ToLower(strings.TrimSpace(configuredName))
		rule, ok := e.rules[name]
		if !ok || rule == nil {
			continue
		}
		triggered, reason := rule.Evaluate(ctx, cfg)
		if !triggered {
			continue
		}
		if strings.TrimSpace(reason) == "" {
			reason = rule.Name()
		}
		return Result{
			RequireMFA: true,
			Rule:       rule.Name(),
			Reason:     reason,
		}
	}
	return Result{}
}
