package logger

import (
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Config configura el logger.
type Config struct {
	// Env define el entorno: "dev" (consola con colores) o "prod" (JSON).
	// Default: "dev"
	Env string

	// Level define el nivel mínimo de log: "debug", "info", "warn", "error".
	// Default: "info"
	Level string

	// ServiceName es el nombre del servicio para incluir en logs.
	// Opcional.
	ServiceName string

	// Version es la versión del servicio.
	// Opcional.
	Version string
}

// build construye el logger según la configuración.
func build(cfg Config) *zap.Logger {
	level := parseLevel(cfg.Level)

	var l *zap.Logger
	var err error

	if strings.ToLower(cfg.Env) == "prod" {
		l, err = buildProd(level, cfg)
	} else {
		l, err = buildDev(level, cfg)
	}

	if err != nil {
		// Fallback a un logger básico si falla
		l, _ = zap.NewProduction()
	}

	return l
}

// buildDev construye un logger para desarrollo con colores.
func buildDev(level zapcore.Level, cfg Config) (*zap.Logger, error) {
	zcfg := zap.NewDevelopmentConfig()
	zcfg.Level = zap.NewAtomicLevelAt(level)

	// Colores para el nivel
	zcfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	// Tiempo legible
	zcfg.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05.000")

	// Caller más corto
	zcfg.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder

	// No stacktrace en dev para info/warn
	zcfg.DisableStacktrace = true

	l, err := zcfg.Build(zap.AddCaller(), zap.AddCallerSkip(1))
	if err != nil {
		return nil, err
	}

	// Agregar campos base si están configurados
	if cfg.ServiceName != "" {
		l = l.With(zap.String("service", cfg.ServiceName))
	}
	if cfg.Version != "" {
		l = l.With(zap.String("version", cfg.Version))
	}

	return l, nil
}

// buildProd construye un logger para producción en JSON.
func buildProd(level zapcore.Level, cfg Config) (*zap.Logger, error) {
	zcfg := zap.NewProductionConfig()
	zcfg.Level = zap.NewAtomicLevelAt(level)

	// Tiempo ISO8601
	zcfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	// Caller
	zcfg.EncoderConfig.EncodeCaller = zapcore.ShortCallerEncoder

	l, err := zcfg.Build(
		zap.AddCaller(),
		zap.AddCallerSkip(1),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)
	if err != nil {
		return nil, err
	}

	// Agregar campos base
	if cfg.ServiceName != "" {
		l = l.With(zap.String("service", cfg.ServiceName))
	}
	if cfg.Version != "" {
		l = l.With(zap.String("version", cfg.Version))
	}

	return l, nil
}

// parseLevel convierte un string a zapcore.Level.
func parseLevel(lvl string) zapcore.Level {
	switch strings.ToLower(strings.TrimSpace(lvl)) {
	case "debug":
		return zapcore.DebugLevel
	case "warn", "warning":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	case "dpanic":
		return zapcore.DPanicLevel
	case "panic":
		return zapcore.PanicLevel
	case "fatal":
		return zapcore.FatalLevel
	default:
		return zapcore.InfoLevel
	}
}
