// Package repository define interfaces de acceso a datos.
package repository

import (
	"context"
	"time"
)

// SessionRepository define operaciones para gestionar sesiones de usuario.
type SessionRepository interface {
	// Create crea una nueva sesión en la base de datos.
	Create(ctx context.Context, input CreateSessionInput) (*Session, error)

	// Get obtiene una sesión por su hash de session_id.
	Get(ctx context.Context, sessionIDHash string) (*Session, error)

	// GetByIDHash es un alias de Get para consistencia con otros repos.
	GetByIDHash(ctx context.Context, sessionIDHash string) (*Session, error)

	// UpdateActivity actualiza el timestamp de última actividad.
	UpdateActivity(ctx context.Context, sessionIDHash string, lastActivity time.Time) error

	// List retorna sesiones con filtros y paginación.
	// El segundo valor retornado es el total count para paginación.
	List(ctx context.Context, filter ListSessionsFilter) ([]Session, int, error)

	// Revoke marca una sesión como revocada.
	Revoke(ctx context.Context, sessionIDHash, revokedBy, reason string) error

	// RevokeAllByUser revoca todas las sesiones activas de un usuario.
	// Retorna el número de sesiones revocadas.
	RevokeAllByUser(ctx context.Context, userID, revokedBy, reason string) (int, error)

	// RevokeAll revoca todas las sesiones activas del tenant.
	// Retorna el número de sesiones revocadas.
	RevokeAll(ctx context.Context, revokedBy, reason string) (int, error)

	// DeleteExpired elimina sesiones expiradas o revocadas.
	// Retorna el número de sesiones eliminadas.
	DeleteExpired(ctx context.Context) (int, error)

	// GetStats retorna estadísticas de sesiones del tenant.
	GetStats(ctx context.Context) (*SessionStats, error)
}

// Session representa una sesión de usuario persistida.
type Session struct {
	ID            string
	UserID        string
	SessionIDHash string

	// Metadata de cliente
	IPAddress  *string
	UserAgent  *string
	DeviceType *string // desktop, mobile, tablet, unknown
	Browser    *string
	OS         *string

	// Geolocalización
	CountryCode *string
	Country     *string
	City        *string

	// Timestamps
	CreatedAt    time.Time
	LastActivity time.Time
	ExpiresAt    time.Time
	RevokedAt    *time.Time
	RevokedBy    *string
	RevokeReason *string
}

// CreateSessionInput contiene los datos para crear una nueva sesión.
type CreateSessionInput struct {
	UserID        string
	SessionIDHash string
	IPAddress     string
	UserAgent     string
	DeviceType    string
	Browser       string
	OS            string
	CountryCode   string
	Country       string
	City          string
	ExpiresAt     time.Time
}

// ListSessionsFilter define filtros para listar sesiones.
type ListSessionsFilter struct {
	UserID     *string // Filtrar por usuario específico
	DeviceType *string // desktop, mobile, tablet
	Status     *string // active, expired, revoked
	Search     *string // Búsqueda en email, IP
	Page       int
	PageSize   int
}

// SessionStats contiene estadísticas de sesiones.
type SessionStats struct {
	TotalActive int
	TotalToday  int
	ByDevice    []SessionDeviceCount
	ByCountry   []SessionCountryCount
}

// SessionDeviceCount contiene conteo por tipo de dispositivo.
type SessionDeviceCount struct {
	DeviceType string
	Count      int
}

// SessionCountryCount contiene conteo por país.
type SessionCountryCount struct {
	Country string
	Count   int
}

// SessionStatus calcula el estado de la sesión.
func (s *Session) SessionStatus() string {
	if s.RevokedAt != nil {
		return "revoked"
	}
	if time.Now().After(s.ExpiresAt) {
		return "expired"
	}
	// Idle si no hay actividad en los últimos 30 minutos
	if time.Since(s.LastActivity) > 30*time.Minute {
		return "idle"
	}
	return "active"
}
