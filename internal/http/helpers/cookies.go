package helpers

import (
	"net/http"
	"strings"
	"time"
)

func ParseSameSite(s string) http.SameSite {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func BuildCookie(name, value, domain, sameSite string, secure bool, ttl time.Duration) *http.Cookie {
	ck := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: ParseSameSite(sameSite),
	}
	if strings.TrimSpace(domain) != "" {
		ck.Domain = domain
	}
	if ttl > 0 {
		ck.Expires = time.Now().Add(ttl).UTC()
		ck.MaxAge = int(ttl.Seconds())
	}
	return ck
}

func BuildDeletionCookie(name, domain, sameSite string, secure bool) *http.Cookie {
	ck := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: ParseSameSite(sameSite),
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
	}
	if strings.TrimSpace(domain) != "" {
		ck.Domain = domain
	}
	return ck
}
