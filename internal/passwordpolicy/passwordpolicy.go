package passwordpolicy

import (
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	secpassword "github.com/dropDatabas3/hellojohn/internal/security/password"
)

const (
	// DefaultMinLength is used when the tenant has no security policy configured.
	DefaultMinLength = 8
	// DefaultMaxLength keeps compatibility with existing limits in the password rules.
	DefaultMaxLength = 128
	// DefaultHistory is used when the tenant has no explicit history setting.
	DefaultHistory = 5
)

const (
	// DefaultSimpleMinLength is the minimum default for newly created tenants.
	DefaultSimpleMinLength = 8
)

// ValidationContext carries optional metadata used by contextual password rules.
type ValidationContext struct {
	Email         string
	Name          string
	PreviousHash  []string
	BlacklistPath string
}

// EffectiveSecurityPolicy resolves effective defaults for nil policies while keeping
// explicit tenant values untouched when a policy exists.
func EffectiveSecurityPolicy(policy *repository.SecurityPolicy) repository.SecurityPolicy {
	if policy == nil {
		return repository.SecurityPolicy{
			PasswordMinLength:   DefaultMinLength,
			RequireUppercase:    true,
			RequireLowercase:    true,
			RequireNumbers:      true,
			RequireSpecialChars: false,
			MaxHistory:          DefaultHistory,
			BreachDetection:     false,
		}
	}

	return *policy
}

// HasConfiguredRules returns true when the tenant has explicitly configured
// at least one password rule, or falls back to minimum defaults gracefully.
func HasConfiguredRules(policy *repository.SecurityPolicy) bool {
	if policy == nil {
		return false
	}

	return policy.PasswordMinLength > 0 ||
		policy.RequireUppercase ||
		policy.RequireLowercase ||
		policy.RequireNumbers ||
		policy.RequireSpecialChars ||
		policy.MaxHistory > 0 ||
		policy.BreachDetection
}

// DefaultSimpleSecurityPolicy returns the minimal recommended policy for new tenants.
func DefaultSimpleSecurityPolicy() repository.SecurityPolicy {
	return repository.SecurityPolicy{
		PasswordMinLength:   DefaultSimpleMinLength,
		RequireUppercase:    false,
		RequireLowercase:    true,
		RequireNumbers:      true,
		RequireSpecialChars: false,
		MaxHistory:          0,
		BreachDetection:     false,
	}
}

// BuildRules converts tenant security policy into PolicyEngine rules.
func BuildRules(policy *repository.SecurityPolicy) []secpassword.PolicyRule {
	effective := EffectiveSecurityPolicy(policy)
	rules := []secpassword.PolicyRule{
		secpassword.MaxLengthRule{Max: DefaultMaxLength},
		secpassword.CommonPasswordRule{},
		secpassword.PersonalInfoRule{},
	}

	if effective.PasswordMinLength > 0 {
		rules = append(rules, secpassword.MinLengthRule{Min: effective.PasswordMinLength})
	}
	if effective.RequireUppercase {
		rules = append(rules, secpassword.RequireUpperRule{Active: true})
	}
	if effective.RequireLowercase {
		rules = append(rules, secpassword.RequireLowerRule{Active: true})
	}
	if effective.RequireNumbers {
		rules = append(rules, secpassword.RequireDigitRule{Active: true})
	}
	if effective.RequireSpecialChars {
		rules = append(rules, secpassword.RequireSymbolRule{Active: true})
	}
	if effective.BreachDetection {
		rules = append(rules, secpassword.NewBreachDetectionRule())
	}
	if effective.MaxHistory > 0 {
		rules = append(rules, secpassword.HistoryRule{MaxHistory: effective.MaxHistory})
	}

	return rules
}

// Validate evaluates a password candidate using policy rules and optional blacklist.
func Validate(candidate string, policy *repository.SecurityPolicy, ctx ValidationContext) []secpassword.Violation {
	var violations []secpassword.Violation

	if p := strings.TrimSpace(ctx.BlacklistPath); p != "" {
		if bl, err := secpassword.GetCachedBlacklist(p); err == nil && bl.Contains(candidate) {
			violations = append(violations, secpassword.Violation{
				Rule:    "blacklist",
				Message: "This password is not allowed.",
			})
		}
	}

	engine := secpassword.NewPolicyEngine(BuildRules(policy)...)
	engineCtx := secpassword.PolicyContext{
		Email:      ctx.Email,
		Name:       ctx.Name,
		PrevHashes: ctx.PreviousHash,
	}

	violations = append(violations, engine.Validate(candidate, engineCtx)...)
	return violations
}
