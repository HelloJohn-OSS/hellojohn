package validation

import "regexp"

// Scope name rules:
// - Lowercase only.
// - Start and end with [a-z0-9].
// - Middle chars may include [a-z0-9:_.-].
// - Length 1..64.
// - No consecutive rule enforced beyond regex (":" / "_" / "." / "-" may repeat) to keep it permissive.
// - Excludes semicolon and whitespace explicitly.
//
// Examples valid: profile, profile:read, email:read:e2e123, a, a_b-c.d:scope2
// Examples invalid: ;hack, Semicolon;hack, BAD, bad space, :leader, trailer:, "", 65+ chars.
var scopeNameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9:_\.-]{0,62}[a-z0-9])?$`)

// ValidScopeName returns true if the provided scope name matches the allowed pattern.
func ValidScopeName(name string) bool {
	return scopeNameRe.MatchString(name)
}
