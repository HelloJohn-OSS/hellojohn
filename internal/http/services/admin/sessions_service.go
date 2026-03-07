// Package admin contiene servicios de administración de sesiones.
package admin

import (
	"context"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/store"
)

// SessionsService provee operaciones administrativas sobre sesiones.
type SessionsService struct {
	dal store.DataAccessLayer
}

// NewSessionsService crea un nuevo servicio de sesiones.
func NewSessionsService(dal store.DataAccessLayer) *SessionsService {
	return &SessionsService{dal: dal}
}

// ListSessionsInput contiene los parámetros para listar sesiones.
type ListSessionsInput struct {
	TenantSlug string
	UserID     *string
	DeviceType *string
	Status     *string
	Search     *string
	Page       int
	PageSize   int
}

// ListSessionsOutput contiene la respuesta de listar sesiones.
type ListSessionsOutput struct {
	Sessions   []SessionItem `json:"sessions"`
	Total      int           `json:"total"`
	Page       int           `json:"page"`
	PageSize   int           `json:"page_size"`
	TotalPages int           `json:"total_pages"`
}

// SessionItem representa una sesión en la lista.
type SessionItem struct {
	ID            string     `json:"id"`
	UserID        string     `json:"user_id"`
	UserEmail     string     `json:"user_email,omitempty"`
	Status        string     `json:"status"`
	IPAddress     string     `json:"ip_address,omitempty"`
	DeviceType    string     `json:"device_type,omitempty"`
	Browser       string     `json:"browser,omitempty"`
	OS            string     `json:"os,omitempty"`
	Country       string     `json:"country,omitempty"`
	City          string     `json:"city,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	LastActivity  time.Time  `json:"last_activity"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	RevokedReason string     `json:"revoked_reason,omitempty"`
}

// List retorna sesiones con filtros y paginación.
func (s *SessionsService) List(ctx context.Context, input ListSessionsInput) (*ListSessionsOutput, error) {
	tda, err := s.dal.ForTenant(ctx, input.TenantSlug)
	if err != nil {
		return nil, err
	}

	if tda.Sessions() == nil {
		return nil, store.ErrNoDBForTenant
	}

	// Defaults
	page := input.Page
	if page < 1 {
		page = 1
	}
	pageSize := input.PageSize
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	sessions, total, err := tda.Sessions().List(ctx, repository.ListSessionsFilter{
		UserID:     input.UserID,
		DeviceType: input.DeviceType,
		Status:     input.Status,
		Search:     input.Search,
		Page:       page,
		PageSize:   pageSize,
	})
	if err != nil {
		return nil, err
	}

	items := make([]SessionItem, 0, len(sessions))
	for _, sess := range sessions {
		item := SessionItem{
			ID:           sess.ID,
			UserID:       sess.UserID,
			Status:       sess.SessionStatus(),
			CreatedAt:    sess.CreatedAt,
			LastActivity: sess.LastActivity,
			ExpiresAt:    sess.ExpiresAt,
			RevokedAt:    sess.RevokedAt,
		}

		if sess.IPAddress != nil {
			item.IPAddress = *sess.IPAddress
		}
		if sess.DeviceType != nil {
			item.DeviceType = *sess.DeviceType
		}
		if sess.Browser != nil {
			item.Browser = *sess.Browser
		}
		if sess.OS != nil {
			item.OS = *sess.OS
		}
		if sess.Country != nil {
			item.Country = *sess.Country
		}
		if sess.City != nil {
			item.City = *sess.City
		}
		if sess.RevokeReason != nil {
			item.RevokedReason = *sess.RevokeReason
		}

		items = append(items, item)
	}

	totalPages := total / pageSize
	if total%pageSize != 0 {
		totalPages++
	}

	return &ListSessionsOutput{
		Sessions:   items,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// RevokeSessionInput contiene los parámetros para revocar una sesión.
type RevokeSessionInput struct {
	TenantSlug    string
	SessionIDHash string
	AdminID       string
	Reason        string
}

// RevokeSession revoca una sesión específica.
func (s *SessionsService) RevokeSession(ctx context.Context, input RevokeSessionInput) error {
	tda, err := s.dal.ForTenant(ctx, input.TenantSlug)
	if err != nil {
		return err
	}

	if tda.Sessions() == nil {
		return store.ErrNoDBForTenant
	}

	return tda.Sessions().Revoke(ctx, input.SessionIDHash, input.AdminID, input.Reason)
}

// RevokeUserSessionsInput contiene los parámetros para revocar sesiones de un usuario.
type RevokeUserSessionsInput struct {
	TenantSlug string
	UserID     string
	AdminID    string
	Reason     string
}

// RevokeUserSessionsOutput contiene la respuesta.
type RevokeUserSessionsOutput struct {
	RevokedCount int `json:"revoked_count"`
}

// RevokeUserSessions revoca todas las sesiones de un usuario.
func (s *SessionsService) RevokeUserSessions(ctx context.Context, input RevokeUserSessionsInput) (*RevokeUserSessionsOutput, error) {
	tda, err := s.dal.ForTenant(ctx, input.TenantSlug)
	if err != nil {
		return nil, err
	}

	if tda.Sessions() == nil {
		return nil, store.ErrNoDBForTenant
	}

	count, err := tda.Sessions().RevokeAllByUser(ctx, input.UserID, input.AdminID, input.Reason)
	if err != nil {
		return nil, err
	}

	return &RevokeUserSessionsOutput{RevokedCount: count}, nil
}

// RevokeAllSessionsInput contiene los parámetros para revocar todas las sesiones.
type RevokeAllSessionsInput struct {
	TenantSlug string
	AdminID    string
	Reason     string
}

// RevokeAllSessions revoca todas las sesiones activas del tenant.
func (s *SessionsService) RevokeAllSessions(ctx context.Context, input RevokeAllSessionsInput) (*RevokeUserSessionsOutput, error) {
	tda, err := s.dal.ForTenant(ctx, input.TenantSlug)
	if err != nil {
		return nil, err
	}

	if tda.Sessions() == nil {
		return nil, store.ErrNoDBForTenant
	}

	count, err := tda.Sessions().RevokeAll(ctx, input.AdminID, input.Reason)
	if err != nil {
		return nil, err
	}

	return &RevokeUserSessionsOutput{RevokedCount: count}, nil
}

// GetSessionInput contiene los parámetros para obtener una sesión.
type GetSessionInput struct {
	TenantSlug    string
	SessionIDHash string
}

// GetSession retorna una sesión específica por su hash.
func (s *SessionsService) GetSession(ctx context.Context, input GetSessionInput) (*SessionItem, error) {
	tda, err := s.dal.ForTenant(ctx, input.TenantSlug)
	if err != nil {
		return nil, err
	}

	if tda.Sessions() == nil {
		return nil, store.ErrNoDBForTenant
	}

	sess, err := tda.Sessions().GetByIDHash(ctx, input.SessionIDHash)
	if err != nil {
		return nil, err
	}

	item := &SessionItem{
		ID:           sess.ID,
		UserID:       sess.UserID,
		Status:       sess.SessionStatus(),
		CreatedAt:    sess.CreatedAt,
		LastActivity: sess.LastActivity,
		ExpiresAt:    sess.ExpiresAt,
		RevokedAt:    sess.RevokedAt,
	}

	if sess.IPAddress != nil {
		item.IPAddress = *sess.IPAddress
	}
	if sess.DeviceType != nil {
		item.DeviceType = *sess.DeviceType
	}
	if sess.Browser != nil {
		item.Browser = *sess.Browser
	}
	if sess.OS != nil {
		item.OS = *sess.OS
	}
	if sess.Country != nil {
		item.Country = *sess.Country
	}
	if sess.City != nil {
		item.City = *sess.City
	}
	if sess.RevokeReason != nil {
		item.RevokedReason = *sess.RevokeReason
	}

	return item, nil
}

// SessionStatsOutput contiene las estadísticas de sesiones.
type SessionStatsOutput struct {
	TotalActive int            `json:"total_active"`
	TotalToday  int            `json:"total_today"`
	ByDevice    []DeviceCount  `json:"by_device"`
	ByCountry   []CountryCount `json:"by_country"`
}

// DeviceCount representa conteo por tipo de dispositivo.
type DeviceCount struct {
	DeviceType string `json:"device_type"`
	Count      int    `json:"count"`
}

// CountryCount representa conteo por país.
type CountryCount struct {
	Country string `json:"country"`
	Count   int    `json:"count"`
}

// GetStatsInput contiene los parámetros para obtener estadísticas.
type GetStatsInput struct {
	TenantSlug string
}

// GetStats retorna estadísticas de sesiones del tenant.
func (s *SessionsService) GetStats(ctx context.Context, input GetStatsInput) (*SessionStatsOutput, error) {
	tda, err := s.dal.ForTenant(ctx, input.TenantSlug)
	if err != nil {
		return nil, err
	}

	if tda.Sessions() == nil {
		return nil, store.ErrNoDBForTenant
	}

	stats, err := tda.Sessions().GetStats(ctx)
	if err != nil {
		return nil, err
	}

	output := &SessionStatsOutput{
		TotalActive: stats.TotalActive,
		TotalToday:  stats.TotalToday,
		ByDevice:    make([]DeviceCount, 0, len(stats.ByDevice)),
		ByCountry:   make([]CountryCount, 0, len(stats.ByCountry)),
	}

	for _, d := range stats.ByDevice {
		output.ByDevice = append(output.ByDevice, DeviceCount{
			DeviceType: d.DeviceType,
			Count:      d.Count,
		})
	}

	for _, c := range stats.ByCountry {
		output.ByCountry = append(output.ByCountry, CountryCount{
			Country: c.Country,
			Count:   c.Count,
		})
	}

	return output, nil
}
