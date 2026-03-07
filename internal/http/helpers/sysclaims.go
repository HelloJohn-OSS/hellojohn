package helpers

import (
	"sort"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/claims"
)

func coerceBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		s := strings.TrimSpace(strings.ToLower(t))
		return s == "true" || s == "1" || s == "yes"
	case float64:
		return t != 0
	case int:
		return t != 0
	case int64:
		return t != 0
	default:
		return false
	}
}

func normUnique(ss []string) []string {
	if len(ss) == 0 {
		return []string{}
	}
	set := map[string]struct{}{}
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		s2 := strings.TrimSpace(s)
		if s2 == "" {
			continue
		}
		s2 = strings.ToLower(s2)
		if _, ok := set[s2]; !ok {
			set[s2] = struct{}{}
			out = append(out, s2)
		}
	}
	sort.Strings(out)
	return out
}

// PutSystemClaims adds system namespace claims (V1: only is_admin).
func PutSystemClaims(baseClaims map[string]any, issuer string, userMeta map[string]any) map[string]any {
	if baseClaims == nil {
		baseClaims = map[string]any{}
	}
	ns := claims.SystemNamespace(issuer)
	isAdmin := false
	if userMeta != nil {
		if v, ok := userMeta["is_admin"]; ok {
			isAdmin = coerceBool(v)
		}
	}
	baseClaims[ns] = map[string]any{
		"is_admin":   isAdmin,
		"roles":      []string{},
		"perms":      []string{},
		"claims_ver": 0,
	}
	return baseClaims
}

// PutSystemClaimsV2 adds system namespace claims with roles/perms (V2: full RBAC).
func PutSystemClaimsV2(baseClaims map[string]any, issuer string, userMeta map[string]any, roles, perms []string) map[string]any {
	if baseClaims == nil {
		baseClaims = map[string]any{}
	}
	ns := claims.SystemNamespace(issuer)
	isAdmin := false
	if userMeta != nil {
		if v, ok := userMeta["is_admin"]; ok {
			isAdmin = coerceBool(v)
		}
	}
	baseClaims[ns] = map[string]any{
		"is_admin":   isAdmin,
		"roles":      normUnique(roles),
		"perms":      normUnique(perms),
		"claims_ver": 1,
	}
	return baseClaims
}
