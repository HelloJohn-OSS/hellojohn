package logger

import (
	"context"

	"go.uber.org/zap"
)

type ctxKey struct{}

// ToContext inyecta un logger en el contexto.
// Usado por middlewares para propagar un logger "scoped" con campos del request.
func ToContext(ctx context.Context, l *zap.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// From extrae el logger del contexto.
// Si no hay logger en el contexto, retorna el singleton.
// Esto permite usar From(ctx) en cualquier parte del código sin preocuparse
// si el middleware inyectó el logger o no.
func From(ctx context.Context) *zap.Logger {
	if ctx == nil {
		return L()
	}
	if v := ctx.Value(ctxKey{}); v != nil {
		if l, ok := v.(*zap.Logger); ok {
			return l
		}
	}
	return L()
}

// FromWithFields extrae el logger del contexto y agrega campos adicionales.
// Shortcut para From(ctx).With(fields...)
func FromWithFields(ctx context.Context, fields ...zap.Field) *zap.Logger {
	return From(ctx).With(fields...)
}
