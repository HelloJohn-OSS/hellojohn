package helpers

import (
	"net"
	"net/http"
	"regexp"
	"strings"

	//controlplane "github.com/dropDatabas3/hellojohn/internal/controlplane/v2"
	"github.com/dropDatabas3/hellojohn/internal/validation"
)

var tenantSlugRe = regexp.MustCompile(`^[a-z0-9\-]{1,64}$`)

// ValidTenantSlug valida un slug de tenant con el patrón usado en v1/v2.
func ValidTenantSlug(slug string) bool {
	s := strings.TrimSpace(slug)
	return tenantSlugRe.MatchString(s)
}

/*
Deprecated: Revisar V2 control-plane para esta lógica.
// ValidRedirectURI aplica la regla estándar del control-plane:
// https obligatorio salvo localhost/127.0.0.1.
func ValidRedirectURI(uri string) bool {
	return controlplane.DefaultValidateRedirectURI(uri)
}
*/

// ValidScopeName reusa la regex permisiva del package validation.
func ValidScopeName(scope string) bool {
	return validation.ValidScopeName(strings.TrimSpace(scope))
}

func ValidScopes(scopes []string) bool {
	for _, s := range scopes {
		if !ValidScopeName(s) {
			return false
		}
	}
	return true
}

// GetClientIP extracts the real client IP from the request.
// Priority: X-Real-IP → X-Forwarded-For (first IP) → RemoteAddr.
// Returns an empty string if no valid IP is found.
func GetClientIP(r *http.Request) string {
	// 1. X-Real-IP (set by nginx / Cloudflare single-IP header)
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		if net.ParseIP(ip) != nil {
			return ip
		}
	}

	// 2. X-Forwarded-For (may contain a comma-separated list; take the first)
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	// 3. RemoteAddr (host:port or bare IP)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && net.ParseIP(host) != nil {
		return host
	}
	if net.ParseIP(r.RemoteAddr) != nil {
		return r.RemoteAddr
	}

	return ""
}
