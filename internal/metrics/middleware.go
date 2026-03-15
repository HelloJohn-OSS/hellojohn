package metrics

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"time"
)

// NewMiddleware retorna un middleware que registra cada request en el collector.
func NewMiddleware(c *Collector) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(rw, r)
			route := r.Pattern
			if route == "" {
				route = r.Method + " " + r.URL.Path
			}
			c.Record(route, rw.statusCode, time.Since(start))
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.written = true
	}
	return rw.ResponseWriter.Write(b)
}

// Preserve optional interfaces required by upgrades/streaming (e.g. WebSocket).
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		conn, readWriter, err := http.NewResponseController(rw.ResponseWriter).Hijack()
		if err != nil {
			return nil, nil, fmt.Errorf("response writer %T does not support hijack: %w", rw.ResponseWriter, err)
		}
		return conn, readWriter, nil
	}
	return hj.Hijack()
}

// Unwrap lets http.ResponseController traverse wrapped writers.
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

func (rw *responseWriter) Flush() {
	if fl, ok := rw.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

func (rw *responseWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := rw.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}
