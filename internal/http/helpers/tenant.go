package helpers

import (
	"net/http"
	"strings"
)

// GetBearerToken extracts the Bearer token from the Authorization header.
func GetBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && strings.EqualFold(auth[0:7], "Bearer ") {
		return auth[7:]
	}
	return ""
}

// ResolveTenantSlug attempts to resolve the tenant slug from various sources.
// Priority: Header (X-Tenant-ID) > Query (tenant_id) > Path (if applicable, handled by router)
func ResolveTenantSlug(r *http.Request) string {
	// 1. Header
	if s := r.Header.Get("X-Tenant-ID"); s != "" {
		return s
	}
	// 2. Query param
	if s := r.URL.Query().Get("tenant_id"); s != "" {
		return s
	}
	return ""
}
