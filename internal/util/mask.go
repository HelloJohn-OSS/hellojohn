package util

import "strings"

func MaskEmail(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	i := strings.IndexByte(s, '@')
	if i <= 0 {
		if s == "" {
			return ""
		}
		if len(s) <= 3 {
			return "***"
		}
		return s[:1] + "…" + s[len(s)-1:]
	}
	user, dom := s[:i], s[i+1:]
	if len(user) > 1 {
		user = user[:1] + "…"
	}
	dparts := strings.Split(dom, ".")
	if len(dparts) > 0 && len(dparts[0]) > 1 {
		dparts[0] = dparts[0][:1] + "…"
	}
	return user + "@" + strings.Join(dparts, ".")
}
