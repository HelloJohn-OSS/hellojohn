package middlewares

import "net/http"

// IPPathRateKey generates a key based on IP + Path (without reading body).
// Useful for auth endpoints to separate limits per endpoint (login vs register)
// without strictly depending on body content.
func IPPathRateKey(r *http.Request) string {
	return clientIP(r) + "|" + r.URL.Path
}
