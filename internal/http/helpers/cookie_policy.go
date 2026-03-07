package helpers

import (
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	sessiondto "github.com/dropDatabas3/hellojohn/internal/http/dto/session"
)

// ApplyTenantCookiePolicyToLoginConfig merges tenant cookie policy into session login config.
// Only non-empty/non-nil policy fields override existing config values.
func ApplyTenantCookiePolicyToLoginConfig(cfg *sessiondto.LoginConfig, policy *repository.CookiePolicy) {
	if cfg == nil || policy == nil {
		return
	}

	applyCookiePolicyCommon(&cfg.CookieDomain, &cfg.SameSite, &cfg.Secure, policy)
}

// ApplyTenantCookiePolicyToLogoutConfig merges tenant cookie policy into session logout config.
// Only non-empty/non-nil policy fields override existing config values.
func ApplyTenantCookiePolicyToLogoutConfig(cfg *sessiondto.SessionLogoutConfig, policy *repository.CookiePolicy) {
	if cfg == nil || policy == nil {
		return
	}

	applyCookiePolicyCommon(&cfg.CookieDomain, &cfg.SameSite, &cfg.Secure, policy)
}

func applyCookiePolicyCommon(domain, sameSite *string, secure *bool, policy *repository.CookiePolicy) {
	if domain != nil {
		if d := strings.TrimSpace(policy.Domain); d != "" {
			*domain = d
		}
	}

	if sameSite != nil {
		switch strings.ToLower(strings.TrimSpace(policy.SameSite)) {
		case "lax":
			*sameSite = "Lax"
		case "strict":
			*sameSite = "Strict"
		case "none":
			*sameSite = "None"
		}
	}

	if secure != nil && policy.Secure != nil {
		*secure = *policy.Secure
	}
}
