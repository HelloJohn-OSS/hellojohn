// Package pg implementa SessionRepository para PostgreSQL.
package pg

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// sessionRepo implementa repository.SessionRepository.
type sessionRepo struct {
	pool *pgxpool.Pool
}

// NewSessionRepo crea un nuevo repositorio de sesiones.
func NewSessionRepo(pool *pgxpool.Pool) repository.SessionRepository {
	return &sessionRepo{pool: pool}
}

// Create inserta una nueva sesión en la base de datos.
func (r *sessionRepo) Create(ctx context.Context, input repository.CreateSessionInput) (*repository.Session, error) {
	query := `
		INSERT INTO sessions (
			user_id, session_id_hash, ip_address, user_agent,
			device_type, browser, os, country_code, country, city,
			expires_at, created_at, last_activity
		) VALUES (
			$1, $2, $3::inet, $4,
			$5, $6, $7, $8, $9, $10,
			$11, NOW(), NOW()
		)
		RETURNING id, user_id, session_id_hash, ip_address, user_agent,
			device_type, browser, os, country_code, country, city,
			created_at, last_activity, expires_at, revoked_at, revoked_by, revoke_reason
	`

	var s repository.Session
	var ipAddr, ua, dt, br, os, cc, country, city *string

	err := r.pool.QueryRow(ctx, query,
		input.UserID,
		input.SessionIDHash,
		nullIfEmpty(input.IPAddress),
		nullIfEmpty(input.UserAgent),
		nullIfEmpty(input.DeviceType),
		nullIfEmpty(input.Browser),
		nullIfEmpty(input.OS),
		nullIfEmpty(input.CountryCode),
		nullIfEmpty(input.Country),
		nullIfEmpty(input.City),
		input.ExpiresAt,
	).Scan(
		&s.ID, &s.UserID, &s.SessionIDHash, &ipAddr, &ua,
		&dt, &br, &os, &cc, &country, &city,
		&s.CreatedAt, &s.LastActivity, &s.ExpiresAt, &s.RevokedAt, &s.RevokedBy, &s.RevokeReason,
	)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	s.IPAddress = ipAddr
	s.UserAgent = ua
	s.DeviceType = dt
	s.Browser = br
	s.OS = os
	s.CountryCode = cc
	s.Country = country
	s.City = city

	return &s, nil
}

// Get obtiene una sesión por su hash.
func (r *sessionRepo) Get(ctx context.Context, sessionIDHash string) (*repository.Session, error) {
	query := `
		SELECT id, user_id, session_id_hash, ip_address, user_agent,
			device_type, browser, os, country_code, country, city,
			created_at, last_activity, expires_at, revoked_at, revoked_by, revoke_reason
		FROM sessions
		WHERE session_id_hash = $1
	`

	var s repository.Session
	var ipAddr, ua, dt, br, os, cc, country, city *string

	err := r.pool.QueryRow(ctx, query, sessionIDHash).Scan(
		&s.ID, &s.UserID, &s.SessionIDHash, &ipAddr, &ua,
		&dt, &br, &os, &cc, &country, &city,
		&s.CreatedAt, &s.LastActivity, &s.ExpiresAt, &s.RevokedAt, &s.RevokedBy, &s.RevokeReason,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}

	s.IPAddress = ipAddr
	s.UserAgent = ua
	s.DeviceType = dt
	s.Browser = br
	s.OS = os
	s.CountryCode = cc
	s.Country = country
	s.City = city

	return &s, nil
}

// UpdateActivity actualiza el timestamp de última actividad.
func (r *sessionRepo) UpdateActivity(ctx context.Context, sessionIDHash string, lastActivity time.Time) error {
	query := `UPDATE sessions SET last_activity = $1 WHERE session_id_hash = $2`
	_, err := r.pool.Exec(ctx, query, lastActivity, sessionIDHash)
	if err != nil {
		return fmt.Errorf("update activity: %w", err)
	}
	return nil
}

// List retorna sesiones filtradas con paginación.
func (r *sessionRepo) List(ctx context.Context, filter repository.ListSessionsFilter) ([]repository.Session, int, error) {
	// Build dynamic WHERE clause
	where := []string{"1=1"}
	args := []any{}
	argIdx := 1

	if filter.UserID != nil && *filter.UserID != "" {
		where = append(where, fmt.Sprintf("user_id = $%d", argIdx))
		args = append(args, *filter.UserID)
		argIdx++
	}

	if filter.DeviceType != nil && *filter.DeviceType != "" {
		where = append(where, fmt.Sprintf("device_type = $%d", argIdx))
		args = append(args, *filter.DeviceType)
		argIdx++
	}

	if filter.Status != nil && *filter.Status != "" {
		switch *filter.Status {
		case "active":
			where = append(where, "revoked_at IS NULL AND expires_at > NOW()")
		case "expired":
			where = append(where, "expires_at <= NOW()")
		case "revoked":
			where = append(where, "revoked_at IS NOT NULL")
		}
	}

	if filter.Search != nil && *filter.Search != "" {
		where = append(where, fmt.Sprintf("(ip_address::text ILIKE $%d OR city ILIKE $%d OR country ILIKE $%d)", argIdx, argIdx, argIdx))
		args = append(args, "%"+*filter.Search+"%")
		argIdx++
	}

	whereClause := strings.Join(where, " AND ")

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sessions WHERE %s", whereClause)
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count sessions: %w", err)
	}

	// Pagination
	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	args = append(args, pageSize, offset)

	// Main query
	query := fmt.Sprintf(`
		SELECT id, user_id, session_id_hash, ip_address, user_agent,
			device_type, browser, os, country_code, country, city,
			created_at, last_activity, expires_at, revoked_at, revoked_by, revoke_reason
		FROM sessions
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []repository.Session
	for rows.Next() {
		var s repository.Session
		var ipAddr, ua, dt, br, os, cc, country, city *string

		if err := rows.Scan(
			&s.ID, &s.UserID, &s.SessionIDHash, &ipAddr, &ua,
			&dt, &br, &os, &cc, &country, &city,
			&s.CreatedAt, &s.LastActivity, &s.ExpiresAt, &s.RevokedAt, &s.RevokedBy, &s.RevokeReason,
		); err != nil {
			return nil, 0, fmt.Errorf("scan session: %w", err)
		}

		s.IPAddress = ipAddr
		s.UserAgent = ua
		s.DeviceType = dt
		s.Browser = br
		s.OS = os
		s.CountryCode = cc
		s.Country = country
		s.City = city

		sessions = append(sessions, s)
	}

	return sessions, total, nil
}

// Revoke marca una sesión como revocada.
func (r *sessionRepo) Revoke(ctx context.Context, sessionIDHash, revokedBy, reason string) error {
	query := `
		UPDATE sessions
		SET revoked_at = NOW(), revoked_by = $1, revoke_reason = $2
		WHERE session_id_hash = $3 AND revoked_at IS NULL
	`
	_, err := r.pool.Exec(ctx, query, revokedBy, reason, sessionIDHash)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}
	return nil
}

// RevokeAllByUser revoca todas las sesiones activas de un usuario.
func (r *sessionRepo) RevokeAllByUser(ctx context.Context, userID, revokedBy, reason string) (int, error) {
	query := `
		UPDATE sessions
		SET revoked_at = NOW(), revoked_by = $1, revoke_reason = $2
		WHERE user_id = $3 AND revoked_at IS NULL AND expires_at > NOW()
	`
	tag, err := r.pool.Exec(ctx, query, revokedBy, reason, userID)
	if err != nil {
		return 0, fmt.Errorf("revoke all by user: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// RevokeAll revoca todas las sesiones activas del tenant.
func (r *sessionRepo) RevokeAll(ctx context.Context, revokedBy, reason string) (int, error) {
	query := `
		UPDATE sessions
		SET revoked_at = NOW(), revoked_by = $1, revoke_reason = $2
		WHERE revoked_at IS NULL AND expires_at > NOW()
	`
	tag, err := r.pool.Exec(ctx, query, revokedBy, reason)
	if err != nil {
		return 0, fmt.Errorf("revoke all: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// DeleteExpired elimina sesiones expiradas o revocadas.
func (r *sessionRepo) DeleteExpired(ctx context.Context) (int, error) {
	query := `DELETE FROM sessions WHERE expires_at < NOW() OR revoked_at IS NOT NULL`
	tag, err := r.pool.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("delete expired: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// GetByIDHash es un alias de Get para consistencia con otros repos.
func (r *sessionRepo) GetByIDHash(ctx context.Context, sessionIDHash string) (*repository.Session, error) {
	return r.Get(ctx, sessionIDHash)
}

// GetStats retorna estadísticas de sesiones.
func (r *sessionRepo) GetStats(ctx context.Context) (*repository.SessionStats, error) {
	stats := &repository.SessionStats{}

	// Total active
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM sessions 
		WHERE revoked_at IS NULL AND expires_at > NOW()
	`).Scan(&stats.TotalActive)
	if err != nil {
		return nil, fmt.Errorf("count active: %w", err)
	}

	// Total today
	err = r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM sessions 
		WHERE created_at >= CURRENT_DATE
	`).Scan(&stats.TotalToday)
	if err != nil {
		return nil, fmt.Errorf("count today: %w", err)
	}

	// By device type
	rows, err := r.pool.Query(ctx, `
		SELECT COALESCE(device_type, 'unknown'), COUNT(*) 
		FROM sessions 
		WHERE revoked_at IS NULL AND expires_at > NOW()
		GROUP BY device_type
	`)
	if err != nil {
		return nil, fmt.Errorf("count by device: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var dc repository.SessionDeviceCount
		if err := rows.Scan(&dc.DeviceType, &dc.Count); err != nil {
			return nil, fmt.Errorf("scan device count: %w", err)
		}
		stats.ByDevice = append(stats.ByDevice, dc)
	}

	// By country
	rows, err = r.pool.Query(ctx, `
		SELECT COALESCE(country, 'Unknown'), COUNT(*) 
		FROM sessions 
		WHERE revoked_at IS NULL AND expires_at > NOW()
		GROUP BY country
		ORDER BY COUNT(*) DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, fmt.Errorf("count by country: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var cc repository.SessionCountryCount
		if err := rows.Scan(&cc.Country, &cc.Count); err != nil {
			return nil, fmt.Errorf("scan country count: %w", err)
		}
		stats.ByCountry = append(stats.ByCountry, cc)
	}

	return stats, nil
}
