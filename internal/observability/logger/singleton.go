package logger

import (
	"sync"

	"go.uber.org/zap"
)

var (
	once     sync.Once
	instance *zap.Logger
)

// Init inicializa el logger singleton con la configuración dada.
// Es idempotente: solo la primera llamada tiene efecto.
// Debe llamarse al inicio de la aplicación (main.go).
func Init(cfg Config) {
	once.Do(func() {
		instance = build(cfg)
	})
}

// L retorna el logger singleton.
// Si Init() no fue llamado, crea un logger por defecto (dev, info).
func L() *zap.Logger {
	if instance == nil {
		Init(Config{Env: "dev", Level: "info"})
	}
	return instance
}

// Named retorna un logger con un nombre de componente.
// El nombre aparece en los logs para identificar el origen.
func Named(name string) *zap.Logger {
	return L().Named(name)
}

// With retorna un logger con campos adicionales.
// Útil para agregar contexto persistente (ej: tenant_id en un service).
func With(fields ...zap.Field) *zap.Logger {
	return L().With(fields...)
}

// Sync flushea cualquier buffer pendiente.
// Debe llamarse con defer en main.go.
func Sync() error {
	if instance != nil {
		return instance.Sync()
	}
	return nil
}
