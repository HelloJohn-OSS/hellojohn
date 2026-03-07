package helpers

import (
	"context"
	"log"
)

type ctxHTTPKey string

const (
	ctxRequestIDKey ctxHTTPKey = "request_id"
	ctxLoggerKey    ctxHTTPKey = "logger"
)

// Logger es una interfaz mínima para logging desde controllers/services.
type Logger interface {
	Printf(format string, v ...any)
}

func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, ctxRequestIDKey, requestID)
}

func RequestID(ctx context.Context) string {
	if v := ctx.Value(ctxRequestIDKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func WithLogger(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, ctxLoggerKey, logger)
}

func GetLogger(ctx context.Context) Logger {
	if v := ctx.Value(ctxLoggerKey); v != nil {
		if l, ok := v.(Logger); ok {
			return l
		}
	}
	return log.Default()
}
