package middlewares

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// =================================================================================
// STATUS RECORDER
// =================================================================================

// statusRecorder captura el status code y bytes escritos de la respuesta.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.wroteHeader {
		return // Evitar llamadas múltiples
	}
	s.status = code
	s.wroteHeader = true
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.status = http.StatusOK
		s.wroteHeader = true
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// Preserve optional interfaces required by upgrades/streaming (e.g. WebSocket).
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		conn, rw, err := http.NewResponseController(s.ResponseWriter).Hijack()
		if err != nil {
			return nil, nil, fmt.Errorf("response writer %T does not support hijack: %w", s.ResponseWriter, err)
		}
		return conn, rw, nil
	}
	return hj.Hijack()
}

// Unwrap lets http.ResponseController traverse wrapped writers.
func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

func (s *statusRecorder) Flush() {
	if fl, ok := s.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

func (s *statusRecorder) Push(target string, opts *http.PushOptions) error {
	if p, ok := s.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

// =================================================================================
// LOGGING MIDDLEWARE
// =================================================================================

// WithLogging registra cada request usando el logger singleton con campos estructurados.
// También inyecta un logger "scoped" en el contexto con request_id, method, path.
//
// Ejemplo de log (dev):
//
//	INFO  [15:04:05.000] request completed  {"request_id": "abc123", "method": "POST", "path": "/v1/auth/login", "status": 200, "bytes": 256, "duration_ms": 45}
//
// Ejemplo de log (prod):
//
//	{"level":"info","ts":"2024-01-15T15:04:05.000Z","msg":"request completed","request_id":"abc123","method":"POST","path":"/v1/auth/login","status":200,"bytes":256,"duration_ms":45}
func WithLogging() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Obtener request ID (ya debería estar en header por WithRequestID)
			requestID := w.Header().Get("X-Request-ID")
			if requestID == "" {
				requestID = GetRequestID(r.Context())
			}

			// Inyectar IP y User-Agent en contexto para uso en services (audit)
			ctx := r.Context()
			ctx = SetClientIP(ctx, clientIP(r))
			ctx = SetUserAgent(ctx, r.UserAgent())

			// Crear logger scoped para este request
			reqLog := logger.L().With(
				logger.RequestID(requestID),
				logger.Method(r.Method),
				logger.Path(r.URL.Path),
			)

			// Agregar tenant si está disponible
			if tda := GetTenant(ctx); tda != nil {
				reqLog = reqLog.With(
					logger.TenantSlug(tda.Slug()),
					logger.TenantID(tda.ID()),
				)
			}

			// Agregar user ID si está disponible
			if userID := GetUserID(ctx); userID != "" {
				reqLog = reqLog.With(logger.UserID(userID))
			}

			// Inyectar logger en contexto para uso en handlers/services
			ctx = logger.ToContext(ctx, reqLog)

			// Capturar respuesta
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			// Procesar request
			next.ServeHTTP(rec, r.WithContext(ctx))

			// Log de finalización
			dur := time.Since(start)
			reqLog.Info("request completed",
				logger.Status(rec.status),
				logger.Bytes(rec.bytes),
				logger.DurationMs(dur.Milliseconds()),
			)
		})
	}
}

// WithDebugLogging es como WithLogging pero también loguea el inicio del request.
// Útil para debugging de requests lentos o que fallan antes de completar.
func WithDebugLogging() Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			requestID := w.Header().Get("X-Request-ID")
			if requestID == "" {
				requestID = GetRequestID(r.Context())
			}

			reqLog := logger.L().With(
				logger.RequestID(requestID),
				logger.Method(r.Method),
				logger.Path(r.URL.Path),
				logger.ClientIP(clientIP(r)),
			)

			// Log de inicio
			reqLog.Debug("request started",
				logger.UserAgent(r.UserAgent()),
			)

			if tda := GetTenant(r.Context()); tda != nil {
				reqLog = reqLog.With(
					logger.TenantSlug(tda.Slug()),
					logger.TenantID(tda.ID()),
				)
			}

			if userID := GetUserID(r.Context()); userID != "" {
				reqLog = reqLog.With(logger.UserID(userID))
			}

			ctx := logger.ToContext(r.Context(), reqLog)
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rec, r.WithContext(ctx))

			dur := time.Since(start)

			// Elegir nivel según status code
			switch {
			case rec.status >= 500:
				reqLog.Error("request failed",
					logger.Status(rec.status),
					logger.Bytes(rec.bytes),
					logger.DurationMs(dur.Milliseconds()),
				)
			case rec.status >= 400:
				reqLog.Warn("request completed with client error",
					logger.Status(rec.status),
					logger.Bytes(rec.bytes),
					logger.DurationMs(dur.Milliseconds()),
				)
			default:
				reqLog.Info("request completed",
					logger.Status(rec.status),
					logger.Bytes(rec.bytes),
					logger.DurationMs(dur.Milliseconds()),
				)
			}
		})
	}
}
