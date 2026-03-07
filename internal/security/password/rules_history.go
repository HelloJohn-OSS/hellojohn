package password

import "strings"

// HistoryRule prevents users from reusing previous passwords.
// It compares candidate passwords against PolicyContext.PrevHashes.
type HistoryRule struct {
	MaxHistory int // maximum number of previous hashes to compare
}

func (r HistoryRule) Name() string { return "password_history" }

func (r HistoryRule) Validate(password string, ctx PolicyContext) *Violation {
	if r.MaxHistory <= 0 || len(ctx.PrevHashes) == 0 {
		return nil
	}

	limit := r.MaxHistory
	if limit > len(ctx.PrevHashes) {
		limit = len(ctx.PrevHashes)
	}

	for _, h := range ctx.PrevHashes[:limit] {
		if matchesHash(password, h) {
			return &Violation{
				Rule:    r.Name(),
				Message: "Password was used recently. Please choose a different one.",
			}
		}
	}

	return nil
}

// matchesHash enforces argon2id-only verification.
func matchesHash(plain, hash string) bool {
	if !strings.HasPrefix(hash, "$argon2id$") {
		return false
	}
	return Verify(plain, hash)
}
