package controlplane

import (
	"fmt"
	"strings"
)

const (
	AuthProfileSPA    = "spa"
	AuthProfileWebSSR = "web_ssr"
	AuthProfileNative = "native"
	AuthProfileM2M    = "m2m"
)

var allowedProfiles = map[string]struct{}{
	AuthProfileSPA:    {},
	AuthProfileWebSSR: {},
	AuthProfileNative: {},
	AuthProfileM2M:    {},
}

// NormalizeAuthProfile normalizes and validates profile names.
// Empty value defaults to "spa" for backward compatibility.
func NormalizeAuthProfile(profile string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(profile))
	if p == "" {
		return AuthProfileSPA, nil
	}
	if _, ok := allowedProfiles[p]; !ok {
		return "", fmt.Errorf("%w: invalid auth profile: %s", ErrBadInput, profile)
	}
	return p, nil
}

// AllowedGrantsForProfile returns the grant allowlist for a given auth profile.
func AllowedGrantsForProfile(profile string) []string {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case AuthProfileM2M:
		return []string{"client_credentials"}
	case AuthProfileWebSSR:
		return []string{"authorization_code", "refresh_token", "client_credentials"}
	case AuthProfileNative:
		return []string{"authorization_code", "refresh_token"}
	default:
		return []string{"authorization_code", "refresh_token"}
	}
}

// ValidateGrant returns true when the grant is allowed for the profile.
func ValidateGrant(profile, grant string) bool {
	grant = strings.ToLower(strings.TrimSpace(grant))
	if grant == "" {
		return false
	}
	for _, allowed := range AllowedGrantsForProfile(profile) {
		if allowed == grant {
			return true
		}
	}
	return false
}

// CoerceGrantTypesForProfile normalizes and auto-corrects grant types for a profile.
func CoerceGrantTypesForProfile(profile string, grants []string) []string {
	profile, _ = NormalizeAuthProfile(profile)

	seen := map[string]struct{}{}
	add := func(v string) {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || !ValidateGrant(profile, v) {
			return
		}
		seen[v] = struct{}{}
	}

	for _, g := range grants {
		add(g)
	}

	// Enforce canonical grants by profile.
	switch profile {
	case AuthProfileM2M:
		seen = map[string]struct{}{"client_credentials": {}}
	case AuthProfileSPA, AuthProfileNative:
		seen["authorization_code"] = struct{}{}
		seen["refresh_token"] = struct{}{}
		delete(seen, "client_credentials")
	case AuthProfileWebSSR:
		seen["authorization_code"] = struct{}{}
		seen["refresh_token"] = struct{}{}
		// If not explicitly configured, keep a DX-friendly default with all web_ssr grants.
		if len(grants) == 0 {
			seen["client_credentials"] = struct{}{}
		}
	}

	ordered := make([]string, 0, len(seen))
	for _, g := range AllowedGrantsForProfile(profile) {
		if _, ok := seen[g]; ok {
			ordered = append(ordered, g)
		}
	}
	return ordered
}
