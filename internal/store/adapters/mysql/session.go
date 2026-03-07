// Package mysql implementa SessionRepository para MySQL.
package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// Verificar que implementa la interfaz
var _ repository.SessionRepository = (*sessionRepo)(nil)

// Create inserta una nueva sesión en la base de datos.
func (r *sessionRepo) Create(ctx context.Context, input repository.CreateSessionInput) (*repository.Session, error) {
	sessionID := uuid.New().String()
	now := time.Now()

	// MySQL no tiene tipo INET, usamos VARCHAR
	const query = `
		INSERT INTO sessions (
			id, user_id, session_id_hash, ip_address, user_agent,
			device_type, browser, os, country_code, country, city,
			expires_at, created_at, last_activity
		) VALUES (
			?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?,
			?, ?, ?
		)
	`

	_, err := r.db.ExecContext(ctx, query,
		sessionID,
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
		now,
		now,
	)
	if err != nil {
		return nil, fmt.Errorf("mysql: create session: %w", err)
	}

	// Build session object
	session := &repository.Session{
		ID:            sessionID,
		UserID:        input.UserID,
		SessionIDHash: input.SessionIDHash,
		CreatedAt:     now,
		LastActivity:  now,
		ExpiresAt:     input.ExpiresAt,
	}

	// Set nullable fields
	if input.IPAddress != "" {
		session.IPAddress = &input.IPAddress
	}
	if input.UserAgent != "" {
		session.UserAgent = &input.UserAgent
	}
	if input.DeviceType != "" {
		session.DeviceType = &input.DeviceType
	}
	if input.Browser != "" {
		session.Browser = &input.Browser
	}
	if input.OS != "" {
		session.OS = &input.OS
	}
	if input.CountryCode != "" {
		session.CountryCode = &input.CountryCode
	}
	if input.Country != "" {
		session.Country = &input.Country
	}
	if input.City != "" {
		session.City = &input.City
	}

	return session, nil
}

// Get obtiene una sesión por su hash.
func (r *sessionRepo) Get(ctx context.Context, sessionIDHash string) (*repository.Session, error) {
	const query = `
		SELECT id, user_id, session_id_hash, ip_address, user_agent,
			device_type, browser, os, country_code, country, city,
			created_at, last_activity, expires_at, revoked_at, revoked_by, revoke_reason
		FROM sessions
		WHERE session_id_hash = ?
	`
	return r.scanSession(ctx, query, sessionIDHash)
}

// GetByIDHash es un alias de Get para consistencia con otros repos.
func (r *sessionRepo) GetByIDHash(ctx context.Context, sessionIDHash string) (*repository.Session, error) {
	return r.Get(ctx, sessionIDHash)
}

// scanSession escanea una sesión de una query.
func (r *sessionRepo) scanSession(ctx context.Context, query string, args ...any) (*repository.Session, error) {
	var s repository.Session
	var ipAddr, ua, dt, br, os, cc, country, city sql.NullString
	var revokedAt sql.NullTime
	var revokedBy, revokeReason sql.NullString

	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&s.ID, &s.UserID, &s.SessionIDHash, &ipAddr, &ua,
		&dt, &br, &os, &cc, &country, &city,
		&s.CreatedAt, &s.LastActivity, &s.ExpiresAt, &revokedAt, &revokedBy, &revokeReason,
	)
	if err == sql.ErrNoRows {
		return nil, nil // Not found, return nil without error (same as PG behavior)
	}
	if err != nil {
		return nil, fmt.Errorf("mysql: get session: %w", err)
	}

	// Map nullable fields
	s.IPAddress = nullStringToPtr(ipAddr)
	s.UserAgent = nullStringToPtr(ua)
	s.DeviceType = nullStringToPtr(dt)
	s.Browser = nullStringToPtr(br)
	s.OS = nullStringToPtr(os)
	s.CountryCode = nullStringToPtr(cc)
	s.Country = nullStringToPtr(country)
	s.City = nullStringToPtr(city)
	s.RevokedAt = nullTimeToPtr(revokedAt)
	s.RevokedBy = nullStringToPtr(revokedBy)
	s.RevokeReason = nullStringToPtr(revokeReason)

	return &s, nil
}

// UpdateActivity actualiza el timestamp de última actividad.
func (r *sessionRepo) UpdateActivity(ctx context.Context, sessionIDHash string, lastActivity time.Time) error {
	const query = `UPDATE sessions SET last_activity = ? WHERE session_id_hash = ?`
	_, err := r.db.ExecContext(ctx, query, lastActivity, sessionIDHash)
	if err != nil {
		return fmt.Errorf("mysql: update activity: %w", err)
	}
	return nil
}

// List retorna sesiones filtradas con paginación.
func (r *sessionRepo) List(ctx context.Context, filter repository.ListSessionsFilter) ([]repository.Session, int, error) {
	// Build dynamic WHERE clause
	where := []string{"1=1"}
	args := []any{}

	if filter.UserID != nil && *filter.UserID != "" {
		where = append(where, "user_id = ?")
		args = append(args, *filter.UserID)
	}

	if filter.DeviceType != nil && *filter.DeviceType != "" {
		where = append(where, "device_type = ?")
		args = append(args, *filter.DeviceType)
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
		// MySQL uses LIKE for case-insensitive search (with proper collation)
		where = append(where, "(ip_address LIKE ? OR city LIKE ? OR country LIKE ?)")
		searchPattern := "%" + *filter.Search + "%"
		args = append(args, searchPattern, searchPattern, searchPattern)
	}

	whereClause := strings.Join(where, " AND ")

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM sessions WHERE %s", whereClause)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("mysql: count sessions: %w", err)
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

	// Main query
	query := fmt.Sprintf(`
		SELECT id, user_id, session_id_hash, ip_address, user_agent,
			device_type, browser, os, country_code, country, city,
			created_at, last_activity, expires_at, revoked_at, revoked_by, revoke_reason
		FROM sessions
		WHERE %s
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`, whereClause)

	queryArgs := append(args, pageSize, offset)
	rows, err := r.db.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("mysql: list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []repository.Session
	for rows.Next() {
		var s repository.Session
		var ipAddr, ua, dt, br, osField, cc, country, city sql.NullString
		var revokedAt sql.NullTime
		var revokedBy, revokeReason sql.NullString

		if err := rows.Scan(
			&s.ID, &s.UserID, &s.SessionIDHash, &ipAddr, &ua,
			&dt, &br, &osField, &cc, &country, &city,
			&s.CreatedAt, &s.LastActivity, &s.ExpiresAt, &revokedAt, &revokedBy, &revokeReason,
		); err != nil {
			return nil, 0, fmt.Errorf("mysql: scan session: %w", err)
		}

		s.IPAddress = nullStringToPtr(ipAddr)
		s.UserAgent = nullStringToPtr(ua)
		s.DeviceType = nullStringToPtr(dt)
		s.Browser = nullStringToPtr(br)
		s.OS = nullStringToPtr(osField)
		s.CountryCode = nullStringToPtr(cc)
		s.Country = nullStringToPtr(country)
		s.City = nullStringToPtr(city)
		s.RevokedAt = nullTimeToPtr(revokedAt)
		s.RevokedBy = nullStringToPtr(revokedBy)
		s.RevokeReason = nullStringToPtr(revokeReason)

		sessions = append(sessions, s)
	}

	return sessions, total, nil
}

// Revoke marca una sesión como revocada.
func (r *sessionRepo) Revoke(ctx context.Context, sessionIDHash, revokedBy, reason string) error {
	const query = `
		UPDATE sessions
		SET revoked_at = NOW(), revoked_by = ?, revoke_reason = ?
		WHERE session_id_hash = ? AND revoked_at IS NULL
	`
	_, err := r.db.ExecContext(ctx, query, revokedBy, reason, sessionIDHash)
	if err != nil {
		return fmt.Errorf("mysql: revoke session: %w", err)
	}
	return nil
}

// RevokeAllByUser revoca todas las sesiones activas de un usuario.
func (r *sessionRepo) RevokeAllByUser(ctx context.Context, userID, revokedBy, reason string) (int, error) {
	const query = `
		UPDATE sessions
		SET revoked_at = NOW(), revoked_by = ?, revoke_reason = ?
		WHERE user_id = ? AND revoked_at IS NULL AND expires_at > NOW()
	`
	result, err := r.db.ExecContext(ctx, query, revokedBy, reason, userID)
	if err != nil {
		return 0, fmt.Errorf("mysql: revoke all by user: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	return int(rowsAffected), nil
}

// RevokeAll revoca todas las sesiones activas del tenant.
func (r *sessionRepo) RevokeAll(ctx context.Context, revokedBy, reason string) (int, error) {
	const query = `
		UPDATE sessions
		SET revoked_at = NOW(), revoked_by = ?, revoke_reason = ?
		WHERE revoked_at IS NULL AND expires_at > NOW()
	`
	result, err := r.db.ExecContext(ctx, query, revokedBy, reason)
	if err != nil {
		return 0, fmt.Errorf("mysql: revoke all: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	return int(rowsAffected), nil
}

// DeleteExpired elimina sesiones expiradas o revocadas.
func (r *sessionRepo) DeleteExpired(ctx context.Context) (int, error) {
	const query = `DELETE FROM sessions WHERE expires_at < NOW() OR revoked_at IS NOT NULL`
	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("mysql: delete expired: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	return int(rowsAffected), nil
}

// GetStats retorna estadísticas de sesiones.
func (r *sessionRepo) GetStats(ctx context.Context) (*repository.SessionStats, error) {
	stats := &repository.SessionStats{}

	// Total active
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM sessions 
		WHERE revoked_at IS NULL AND expires_at > NOW()
	`).Scan(&stats.TotalActive)
	if err != nil {
		return nil, fmt.Errorf("mysql: count active: %w", err)
	}

	// Total today
	err = r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM sessions 
		WHERE created_at >= CURDATE()
	`).Scan(&stats.TotalToday)
	if err != nil {
		return nil, fmt.Errorf("mysql: count today: %w", err)
	}

	// By device type
	rows, err := r.db.QueryContext(ctx, `
		SELECT COALESCE(device_type, 'unknown'), COUNT(*) 
		FROM sessions 
		WHERE revoked_at IS NULL AND expires_at > NOW()
		GROUP BY device_type
	`)
	if err != nil {
		return nil, fmt.Errorf("mysql: count by device: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var dc repository.SessionDeviceCount
		if err := rows.Scan(&dc.DeviceType, &dc.Count); err != nil {
			return nil, fmt.Errorf("mysql: scan device count: %w", err)
		}
		stats.ByDevice = append(stats.ByDevice, dc)
	}

	// By country
	rows, err = r.db.QueryContext(ctx, `
		SELECT COALESCE(country, 'Unknown'), COUNT(*) 
		FROM sessions 
		WHERE revoked_at IS NULL AND expires_at > NOW()
		GROUP BY country
		ORDER BY COUNT(*) DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, fmt.Errorf("mysql: count by country: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var cc repository.SessionCountryCount
		if err := rows.Scan(&cc.Country, &cc.Count); err != nil {
			return nil, fmt.Errorf("mysql: scan country count: %w", err)
		}
		stats.ByCountry = append(stats.ByCountry, cc)
	}

	return stats, nil
}
