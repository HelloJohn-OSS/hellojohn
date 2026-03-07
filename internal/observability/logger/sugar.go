package logger

import (
	"context"

	"go.uber.org/zap"
)

// S retorna el SugaredLogger del singleton.
// Útil para logs rápidos con formato printf-style.
//
// Ejemplo:
//
//	logger.S().Infof("user %s created", userID)
//	logger.S().Errorw("failed to create user", "error", err, "user_id", userID)
func S() *zap.SugaredLogger {
	return L().Sugar()
}

// SFrom extrae el SugaredLogger del contexto.
func SFrom(ctx context.Context) *zap.SugaredLogger {
	return From(ctx).Sugar()
}
