// Package logger provides a singleton Zap logger with context-based scoping.
//
// # Design Decisions
//
//   - Singleton: Una sola instancia global inicializada con Init().
//   - Context Scoping: Cada request puede tener su propio logger "scoped" con campos
//     adicionales (request_id, tenant_id, etc.) sin crear un nuevo core.
//   - Environments: "dev" usa consola con colores, "prod" usa JSON.
//   - Levels: debug, info, warn, error (configurable via LOG_LEVEL).
//
// # Usage
//
// Inicialización (una vez en main.go):
//
//	logger.Init(logger.Config{
//	    Env:   os.Getenv("APP_ENV"),   // "dev" o "prod"
//	    Level: os.Getenv("LOG_LEVEL"), // "debug", "info", "warn", "error"
//	})
//	defer logger.L().Sync()
//
// En handlers/services (con contexto):
//
//	log := logger.From(ctx)
//	log.Info("processing request", logger.UserID(userID))
//
// Sin contexto (fallback a singleton):
//
//	logger.L().Info("application started")
package logger
