package logger

import (
	"time"

	"go.uber.org/zap"
)

// =================================================================================
// CAMPOS ESTÁNDAR - HTTP
// =================================================================================

// RequestID crea un campo para el ID del request.
func RequestID(v string) zap.Field {
	return zap.String("request_id", v)
}

// Method crea un campo para el método HTTP.
func Method(v string) zap.Field {
	return zap.String("method", v)
}

// Path crea un campo para el path del request.
func Path(v string) zap.Field {
	return zap.String("path", v)
}

// Status crea un campo para el status code HTTP.
func Status(v int) zap.Field {
	return zap.Int("status", v)
}

// Duration crea un campo para la duración del request.
func Duration(v time.Duration) zap.Field {
	return zap.Duration("duration", v)
}

// DurationMs crea un campo para la duración en milisegundos.
func DurationMs(v int64) zap.Field {
	return zap.Int64("duration_ms", v)
}

// Bytes crea un campo para los bytes de respuesta.
func Bytes(v int) zap.Field {
	return zap.Int("bytes", v)
}

// ClientIP crea un campo para la IP del cliente.
func ClientIP(v string) zap.Field {
	return zap.String("client_ip", v)
}

// UserAgent crea un campo para el User-Agent.
func UserAgent(v string) zap.Field {
	return zap.String("user_agent", v)
}

// =================================================================================
// CAMPOS ESTÁNDAR - NEGOCIO
// =================================================================================

// TenantID crea un campo para el ID del tenant.
func TenantID(v string) zap.Field {
	return zap.String("tenant_id", v)
}

// TenantSlug crea un campo para el slug del tenant.
func TenantSlug(v string) zap.Field {
	return zap.String("tenant_slug", v)
}

// UserID crea un campo para el ID del usuario.
func UserID(v string) zap.Field {
	return zap.String("user_id", v)
}

// ClientID crea un campo para el ID del cliente OAuth.
func ClientID(v string) zap.Field {
	return zap.String("client_id", v)
}

// Email crea un campo para el email (usar con cuidado en prod).
func Email(v string) zap.Field {
	return zap.String("email", v)
}

// =================================================================================
// CAMPOS ESTÁNDAR - SISTEMA
// =================================================================================

// Component crea un campo para el componente/módulo.
func Component(v string) zap.Field {
	return zap.String("component", v)
}

// Op crea un campo para la operación actual.
func Op(v string) zap.Field {
	return zap.String("op", v)
}

// Layer crea un campo para la capa (handler, service, repository).
func Layer(v string) zap.Field {
	return zap.String("layer", v)
}

// Err crea un campo para un error.
func Err(err error) zap.Field {
	return zap.Error(err)
}

// =================================================================================
// CAMPOS ESTÁNDAR - DATOS
// =================================================================================

// Count crea un campo para un conteo.
func Count(v int) zap.Field {
	return zap.Int("count", v)
}

// ID crea un campo genérico para un ID.
func ID(v string) zap.Field {
	return zap.String("id", v)
}

// Key crea un campo genérico para una clave.
func Key(v string) zap.Field {
	return zap.String("key", v)
}

// Value crea un campo genérico para un valor (string).
func Value(v string) zap.Field {
	return zap.String("value", v)
}

// Any crea un campo genérico para cualquier tipo.
func Any(key string, v any) zap.Field {
	return zap.Any(key, v)
}

// String crea un campo string genérico.
func String(key, v string) zap.Field {
	return zap.String(key, v)
}

// Int crea un campo int genérico.
func Int(key string, v int) zap.Field {
	return zap.Int(key, v)
}

// Bool crea un campo bool genérico.
func Bool(key string, v bool) zap.Field {
	return zap.Bool(key, v)
}
