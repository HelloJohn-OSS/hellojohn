package middlewares

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/http/errors"
)

// =================================================================================
// RATE LIMITER INTERFACE
// =================================================================================

// RateLimitResult contiene el resultado de una consulta al rate limiter.
type RateLimitResult struct {
	Allowed     bool
	Remaining   int64
	RetryAfter  time.Duration
	WindowTTL   time.Duration
	CurrentHits int64
}

// RateLimiter define la interfaz mínima para un rate limiter.
type RateLimiter interface {
	Allow(ctx context.Context, key string) (RateLimitResult, error)
}

// =================================================================================
// RATE LIMIT MIDDLEWARE
// =================================================================================

// clientIP extrae la IP del cliente, considerando proxies.
func clientIP(r *http.Request) string {
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		parts := strings.Split(xf, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

// extractJSONField lee hasta max bytes del body (si es JSON) para extraer un campo y repone el body.
func extractJSONField(r *http.Request, field string, max int64) string {
	if r.Method != http.MethodPost ||
		!strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		return ""
	}
	var buf bytes.Buffer
	_, _ = io.CopyN(&buf, r.Body, max)
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))

	var tmp map[string]any
	if err := json.Unmarshal(buf.Bytes(), &tmp); err == nil {
		if v, ok := tmp[field]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

// RateKeyFunc define cómo generar la clave de rate limiting.
type RateKeyFunc func(r *http.Request) string

// DefaultRateKey genera una clave basada en IP, path y opcionalmente client_id.
func DefaultRateKey(r *http.Request) string {
	ip := clientIP(r)
	path := r.URL.Path

	// Optimization: Skip body extraction for admin paths to avoid truncating large payloads
	if strings.HasPrefix(path, "/v1/admin") || strings.HasPrefix(path, "/v2/admin") || strings.HasPrefix(path, "/t/") {
		return ip + "|" + path + "|-"
	}

	clientID := extractJSONField(r, "client_id", 4096)
	if clientID == "" {
		clientID = "-"
	}
	return ip + "|" + path + "|" + clientID
}

// IPOnlyRateKey genera una clave basada solo en IP.
// Útil para rate limiting de login donde no queremos leer el body.
func IPOnlyRateKey(r *http.Request) string {
	return clientIP(r)
}

// RateLimitConfig configura el comportamiento del middleware de rate limiting.
type RateLimitConfig struct {
	Limiter   RateLimiter
	KeyFunc   RateKeyFunc
	Whitelist []string // Paths que se excluyen del rate limiting (ej: /healthz)
}

// WithRateLimit crea un middleware de rate limiting.
func WithRateLimit(cfg RateLimitConfig) Middleware {
	if cfg.Limiter == nil {
		// Si no hay limiter, no hacemos nada
		return func(next http.Handler) http.Handler { return next }
	}
	if cfg.KeyFunc == nil {
		cfg.KeyFunc = DefaultRateKey
	}

	whitelistSet := make(map[string]struct{})
	for _, p := range cfg.Whitelist {
		whitelistSet[p] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Whitelist check
			if _, ok := whitelistSet[r.URL.Path]; ok {
				next.ServeHTTP(w, r)
				return
			}

			key := cfg.KeyFunc(r)
			res, err := cfg.Limiter.Allow(r.Context(), key)
			if err != nil {
				log.Printf(`{"level":"warn","msg":"rate_limit_error","err":"%v"}`, err)
				// En caso de error del limiter, permitimos el request
				next.ServeHTTP(w, r)
				return
			}

			if !res.Allowed {
				if res.RetryAfter > 0 {
					w.Header().Set("Retry-After", strconv.Itoa(int(res.RetryAfter.Seconds())))
				}
				if res.WindowTTL > 0 {
					resetAt := time.Now().Add(res.WindowTTL).Unix()
					w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetAt, 10))
				}
				errors.WriteError(w, errors.ErrRateLimitExceeded)
				return
			}

			// Headers informativos
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", res.Remaining))
			if res.WindowTTL > 0 {
				resetAt := time.Now().Add(res.WindowTTL).Unix()
				w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetAt, 10))
			}

			next.ServeHTTP(w, r)
		})
	}
}
