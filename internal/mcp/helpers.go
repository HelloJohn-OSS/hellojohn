package mcp

import (
	"fmt"
	"net/url"
	"strings"
)

// errMissing returns a formatted error for missing required arguments.
func errMissing(fields string) error {
	return fmt.Errorf("missing required argument(s): %s", fields)
}

// adminPath builds a safely-escaped admin API path.
// Each segment is url.PathEscape'd to prevent path traversal.
// Usage: adminPath("tenants", tenantSlug, "clients", clientID)
func adminPath(segments ...string) string {
	parts := make([]string, len(segments))
	for i, s := range segments {
		parts[i] = url.PathEscape(s)
	}
	return "/v2/admin/" + strings.Join(parts, "/")
}

// splitAndTrim splits s by sep, trims each element, and removes empty strings.
func splitAndTrim(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}
