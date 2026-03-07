package pg_shared

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// ─── sharedTokenRepo ──────────────────────────────────────────────

type sharedTokenRepo struct {
	pool     *pgxpool.Pool
	tenantID uuid.UUID
}

func (r *sharedTokenRepo) Create(ctx context.Context, input repository.CreateRefreshTokenInput) (string, error) {
	var id string
	err := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		const query = `
			INSERT INTO refresh_token (tenant_id, user_id, client_id_text, token_hash, issued_at, expires_at, rotated_from)
			VALUES ($1, $2, $3, $4, NOW(), NOW() + $5::interval, $6)
			RETURNING id
		`
		ttl := fmt.Sprintf("%d seconds", input.TTLSeconds)
		return tx.QueryRow(ctx, query,
			r.tenantID, input.UserID, input.ClientID, input.TokenHash, ttl, input.RotatedFrom,
		).Scan(&id)
	})
	return id, err
}

func (r *sharedTokenRepo) GetByHash(ctx context.Context, tokenHash string) (*repository.RefreshToken, error) {
	const query = `
		SELECT id, user_id, client_id_text, token_hash, issued_at, expires_at, rotated_from, revoked_at
		FROM refresh_token WHERE tenant_id = $1 AND token_hash = $2
	`
	var token repository.RefreshToken
	err := r.pool.QueryRow(ctx, query, r.tenantID, tokenHash).Scan(
		&token.ID, &token.UserID, &token.ClientID,
		&token.TokenHash, &token.IssuedAt, &token.ExpiresAt, &token.RotatedFrom, &token.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("pg_shared: GetByHash: %w", err)
	}
	token.TenantID = r.tenantID.String()
	return &token, nil
}

func (r *sharedTokenRepo) Revoke(ctx context.Context, tokenID string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `UPDATE refresh_token SET revoked_at = NOW() WHERE tenant_id = $1 AND id = $2`, r.tenantID, tokenID)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *sharedTokenRepo) GetFamilyRoot(ctx context.Context, tokenID string) (string, error) {
	// Single recursive CTE replaces the previous sequential loop of up to 256 queries.
	const query = `
		WITH RECURSIVE chain AS (
			SELECT id, rotated_from
			FROM refresh_token
			WHERE tenant_id = $1 AND id = $2
			UNION ALL
			SELECT rt.id, rt.rotated_from
			FROM refresh_token rt
			INNER JOIN chain c ON rt.id = c.rotated_from
			WHERE rt.tenant_id = $1
		)
		SELECT id FROM chain WHERE rotated_from IS NULL
		LIMIT 1
	`
	var rootID string
	if err := r.pool.QueryRow(ctx, query, r.tenantID, tokenID).Scan(&rootID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", repository.ErrNotFound
		}
		return "", fmt.Errorf("pg_shared: GetFamilyRoot: %w", err)
	}
	return rootID, nil
}

func (r *sharedTokenRepo) RevokeFamily(ctx context.Context, familyRootID string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		// CRITICAL: tenant_id in seed AND recursive step to prevent cross-tenant recursion
		const query = `
			WITH RECURSIVE family AS (
				SELECT id FROM refresh_token WHERE tenant_id = $1 AND id = $2
				UNION ALL
				SELECT rt.id
				FROM refresh_token rt
				INNER JOIN family f ON rt.rotated_from = f.id
				WHERE rt.tenant_id = $1
			)
			UPDATE refresh_token
			SET revoked_at = NOW()
			WHERE id IN (SELECT id FROM family) AND revoked_at IS NULL AND tenant_id = $1
		`
		_, err := tx.Exec(ctx, query, r.tenantID, familyRootID)
		return err
	})
}

func (r *sharedTokenRepo) RevokeAllByUser(ctx context.Context, userID, clientID string) (int, error) {
	var count int
	err := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		var query string
		var args []any
		if clientID != "" {
			query = `UPDATE refresh_token SET revoked_at = NOW() WHERE tenant_id = $1 AND user_id = $2 AND client_id_text = $3 AND revoked_at IS NULL`
			args = []any{r.tenantID, userID, clientID}
		} else {
			query = `UPDATE refresh_token SET revoked_at = NOW() WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL`
			args = []any{r.tenantID, userID}
		}
		tag, err := tx.Exec(ctx, query, args...)
		count = int(tag.RowsAffected())
		return err
	})
	return count, err
}

func (r *sharedTokenRepo) RevokeAllByClient(ctx context.Context, clientID string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE refresh_token SET revoked_at = NOW() WHERE tenant_id = $1 AND client_id_text = $2 AND revoked_at IS NULL`,
			r.tenantID, clientID)
		return err
	})
}

func (r *sharedTokenRepo) GetByID(ctx context.Context, tokenID string) (*repository.RefreshToken, error) {
	const query = `
		SELECT t.id, t.user_id, t.client_id_text, t.token_hash, t.issued_at, t.expires_at, t.rotated_from, t.revoked_at,
		       COALESCE(u.email, '') AS user_email
		FROM refresh_token t
		LEFT JOIN app_user u ON u.id = t.user_id AND u.tenant_id = $1
		WHERE t.tenant_id = $1 AND t.id = $2
	`
	var token repository.RefreshToken
	err := r.pool.QueryRow(ctx, query, r.tenantID, tokenID).Scan(
		&token.ID, &token.UserID, &token.ClientID,
		&token.TokenHash, &token.IssuedAt, &token.ExpiresAt, &token.RotatedFrom, &token.RevokedAt,
		&token.UserEmail,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("pg_shared: GetByID: %w", err)
	}
	token.TenantID = r.tenantID.String()
	return &token, nil
}

func (r *sharedTokenRepo) List(ctx context.Context, filter repository.ListTokensFilter) ([]repository.RefreshToken, error) {
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.PageSize < 1 {
		filter.PageSize = 50
	}
	if filter.PageSize > 200 {
		filter.PageSize = 200
	}
	offset := (filter.Page - 1) * filter.PageSize

	query := `
		SELECT t.id, t.user_id, t.client_id_text, t.token_hash, t.issued_at, t.expires_at, t.rotated_from, t.revoked_at,
		       COALESCE(u.email, '') AS user_email
		FROM refresh_token t
		LEFT JOIN app_user u ON u.id = t.user_id AND u.tenant_id = $1
		WHERE t.tenant_id = $1
	`
	args := []any{r.tenantID}
	argIndex := 2

	if filter.UserID != nil && *filter.UserID != "" {
		query += fmt.Sprintf(" AND t.user_id = $%d", argIndex)
		args = append(args, *filter.UserID)
		argIndex++
	}
	if filter.ClientID != nil && *filter.ClientID != "" {
		query += fmt.Sprintf(" AND t.client_id_text = $%d", argIndex)
		args = append(args, *filter.ClientID)
		argIndex++
	}
	if filter.Status != nil && *filter.Status != "" {
		switch *filter.Status {
		case "active":
			query += " AND t.revoked_at IS NULL AND t.expires_at > NOW()"
		case "expired":
			query += " AND t.revoked_at IS NULL AND t.expires_at <= NOW()"
		case "revoked":
			query += " AND t.revoked_at IS NOT NULL"
		}
	}
	if filter.Search != nil && *filter.Search != "" {
		query += fmt.Sprintf(" AND u.email ILIKE $%d", argIndex)
		args = append(args, "%"+*filter.Search+"%")
		argIndex++
	}

	query += fmt.Sprintf(" ORDER BY t.issued_at DESC LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
	args = append(args, filter.PageSize, offset)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []repository.RefreshToken
	for rows.Next() {
		var token repository.RefreshToken
		if err := rows.Scan(
			&token.ID, &token.UserID, &token.ClientID,
			&token.TokenHash, &token.IssuedAt, &token.ExpiresAt, &token.RotatedFrom, &token.RevokedAt,
			&token.UserEmail,
		); err != nil {
			return nil, err
		}
		token.TenantID = r.tenantID.String()
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

func (r *sharedTokenRepo) Count(ctx context.Context, filter repository.ListTokensFilter) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM refresh_token t
		LEFT JOIN app_user u ON u.id = t.user_id AND u.tenant_id = $1
		WHERE t.tenant_id = $1
	`
	args := []any{r.tenantID}
	argIndex := 2

	if filter.UserID != nil && *filter.UserID != "" {
		query += fmt.Sprintf(" AND t.user_id = $%d", argIndex)
		args = append(args, *filter.UserID)
		argIndex++
	}
	if filter.ClientID != nil && *filter.ClientID != "" {
		query += fmt.Sprintf(" AND t.client_id_text = $%d", argIndex)
		args = append(args, *filter.ClientID)
		argIndex++
	}
	if filter.Status != nil && *filter.Status != "" {
		switch *filter.Status {
		case "active":
			query += " AND t.revoked_at IS NULL AND t.expires_at > NOW()"
		case "expired":
			query += " AND t.revoked_at IS NULL AND t.expires_at <= NOW()"
		case "revoked":
			query += " AND t.revoked_at IS NOT NULL"
		}
	}
	if filter.Search != nil && *filter.Search != "" {
		query += fmt.Sprintf(" AND u.email ILIKE $%d", argIndex)
		args = append(args, "%"+*filter.Search+"%")
	}

	var count int
	err := r.pool.QueryRow(ctx, query, args...).Scan(&count)
	return count, err
}

func (r *sharedTokenRepo) RevokeAll(ctx context.Context) (int, error) {
	var count int
	err := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		tag, txErr := tx.Exec(ctx,
			`UPDATE refresh_token SET revoked_at = NOW() WHERE tenant_id = $1 AND revoked_at IS NULL`,
			r.tenantID)
		count = int(tag.RowsAffected())
		return txErr
	})
	return count, err
}

func (r *sharedTokenRepo) GetStats(ctx context.Context) (*repository.TokenStats, error) {
	stats := &repository.TokenStats{}

	// Wrap all 4 queries in a single read transaction for a consistent snapshot.
	err := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			SELECT COUNT(*) FROM refresh_token
			WHERE tenant_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
		`, r.tenantID).Scan(&stats.TotalActive); err != nil {
			return fmt.Errorf("GetStats TotalActive: %w", err)
		}

		if err := tx.QueryRow(ctx, `
			SELECT COUNT(*) FROM refresh_token
			WHERE tenant_id = $1 AND issued_at >= CURRENT_DATE
		`, r.tenantID).Scan(&stats.IssuedToday); err != nil {
			return fmt.Errorf("GetStats IssuedToday: %w", err)
		}

		if err := tx.QueryRow(ctx, `
			SELECT COUNT(*) FROM refresh_token
			WHERE tenant_id = $1 AND revoked_at >= CURRENT_DATE
		`, r.tenantID).Scan(&stats.RevokedToday); err != nil {
			return fmt.Errorf("GetStats RevokedToday: %w", err)
		}

		if err := tx.QueryRow(ctx, `
			SELECT COALESCE(
				AVG(EXTRACT(EPOCH FROM (
					COALESCE(revoked_at, LEAST(expires_at, NOW())) - issued_at
				)) / 3600.0), 0
			)
			FROM refresh_token
			WHERE tenant_id = $1 AND (revoked_at IS NOT NULL OR expires_at <= NOW())
		`, r.tenantID).Scan(&stats.AvgLifetimeHours); err != nil {
			return fmt.Errorf("GetStats AvgLifetimeHours: %w", err)
		}

		rows, err := tx.Query(ctx, `
			SELECT client_id_text, COUNT(*) as cnt
			FROM refresh_token
			WHERE tenant_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
			GROUP BY client_id_text
			ORDER BY cnt DESC
			LIMIT 10
		`, r.tenantID)
		if err != nil {
			return fmt.Errorf("GetStats ByClient query: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var cc repository.ClientTokenCount
			if err := rows.Scan(&cc.ClientID, &cc.Count); err != nil {
				return err
			}
			stats.ByClient = append(stats.ByClient, cc)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return stats, nil
}

// ─── sharedSessionRepo ───────────────────────────────────────────

type sharedSessionRepo struct {
	pool     *pgxpool.Pool
	tenantID uuid.UUID
}

func (r *sharedSessionRepo) Create(ctx context.Context, input repository.CreateSessionInput) (*repository.Session, error) {
	var s repository.Session
	err := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		const query = `
			INSERT INTO sessions (
				tenant_id, user_id, session_id_hash, ip_address, user_agent,
				device_type, browser, os, country_code, country, city,
				expires_at, created_at, last_activity
			) VALUES (
				$1, $2, $3, $4::inet, $5,
				$6, $7, $8, $9, $10, $11,
				$12, NOW(), NOW()
			)
			RETURNING id, user_id, session_id_hash, ip_address, user_agent,
				device_type, browser, os, country_code, country, city,
				created_at, last_activity, expires_at, revoked_at, revoked_by, revoke_reason
		`
		var ipAddr, ua, dt, br, os, cc, country, city *string
		err := tx.QueryRow(ctx, query,
			r.tenantID,
			input.UserID,
			input.SessionIDHash,
			sanitizeIP(input.IPAddress),
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
			return fmt.Errorf("create session: %w", err)
		}
		s.IPAddress = ipAddr
		s.UserAgent = ua
		s.DeviceType = dt
		s.Browser = br
		s.OS = os
		s.CountryCode = cc
		s.Country = country
		s.City = city
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *sharedSessionRepo) Get(ctx context.Context, sessionIDHash string) (*repository.Session, error) {
	const query = `
		SELECT id, user_id, session_id_hash, ip_address, user_agent,
			device_type, browser, os, country_code, country, city,
			created_at, last_activity, expires_at, revoked_at, revoked_by, revoke_reason
		FROM sessions
		WHERE tenant_id = $1 AND session_id_hash = $2
	`
	var s repository.Session
	var ipAddr, ua, dt, br, os, cc, country, city *string

	err := r.pool.QueryRow(ctx, query, r.tenantID, sessionIDHash).Scan(
		&s.ID, &s.UserID, &s.SessionIDHash, &ipAddr, &ua,
		&dt, &br, &os, &cc, &country, &city,
		&s.CreatedAt, &s.LastActivity, &s.ExpiresAt, &s.RevokedAt, &s.RevokedBy, &s.RevokeReason,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
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

func (r *sharedSessionRepo) GetByIDHash(ctx context.Context, sessionIDHash string) (*repository.Session, error) {
	return r.Get(ctx, sessionIDHash)
}

func (r *sharedSessionRepo) UpdateActivity(ctx context.Context, sessionIDHash string, lastActivity time.Time) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE sessions SET last_activity = $3 WHERE tenant_id = $1 AND session_id_hash = $2`,
			r.tenantID, sessionIDHash, lastActivity)
		return err
	})
}

func (r *sharedSessionRepo) List(ctx context.Context, filter repository.ListSessionsFilter) ([]repository.Session, int, error) {
	where := []string{"tenant_id = $1"}
	args := []any{r.tenantID}
	argIdx := 2

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

	var total int
	if err := r.pool.QueryRow(ctx, fmt.Sprintf("SELECT COUNT(*) FROM sessions WHERE %s", whereClause), args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count sessions: %w", err)
	}

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

func (r *sharedSessionRepo) Revoke(ctx context.Context, sessionIDHash, revokedBy, reason string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			UPDATE sessions
			SET revoked_at = NOW(), revoked_by = $3, revoke_reason = $4
			WHERE tenant_id = $1 AND session_id_hash = $2 AND revoked_at IS NULL
		`, r.tenantID, sessionIDHash, revokedBy, reason)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *sharedSessionRepo) RevokeAllByUser(ctx context.Context, userID, revokedBy, reason string) (int, error) {
	var count int
	err := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		tag, txErr := tx.Exec(ctx, `
			UPDATE sessions
			SET revoked_at = NOW(), revoked_by = $3, revoke_reason = $4
			WHERE tenant_id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > NOW()
		`, r.tenantID, userID, revokedBy, reason)
		count = int(tag.RowsAffected())
		return txErr
	})
	return count, err
}

func (r *sharedSessionRepo) RevokeAll(ctx context.Context, revokedBy, reason string) (int, error) {
	var count int
	err := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		tag, txErr := tx.Exec(ctx, `
			UPDATE sessions
			SET revoked_at = NOW(), revoked_by = $2, revoke_reason = $3
			WHERE tenant_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
		`, r.tenantID, revokedBy, reason)
		count = int(tag.RowsAffected())
		return txErr
	})
	return count, err
}

func (r *sharedSessionRepo) DeleteExpired(ctx context.Context) (int, error) {
	var count int
	err := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		tag, txErr := tx.Exec(ctx,
			`DELETE FROM sessions WHERE tenant_id = $1 AND (expires_at < NOW() OR revoked_at IS NOT NULL)`,
			r.tenantID)
		count = int(tag.RowsAffected())
		return txErr
	})
	return count, err
}

func (r *sharedSessionRepo) GetStats(ctx context.Context) (*repository.SessionStats, error) {
	stats := &repository.SessionStats{}

	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM sessions
		WHERE tenant_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
	`, r.tenantID).Scan(&stats.TotalActive)
	if err != nil {
		return nil, err
	}

	err = r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM sessions
		WHERE tenant_id = $1 AND created_at >= CURRENT_DATE
	`, r.tenantID).Scan(&stats.TotalToday)
	if err != nil {
		return nil, err
	}

	rows, err := r.pool.Query(ctx, `
		SELECT COALESCE(device_type, 'unknown'), COUNT(*)
		FROM sessions
		WHERE tenant_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
		GROUP BY device_type
	`, r.tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var dc repository.SessionDeviceCount
		if err := rows.Scan(&dc.DeviceType, &dc.Count); err != nil {
			return nil, err
		}
		stats.ByDevice = append(stats.ByDevice, dc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows2, err := r.pool.Query(ctx, `
		SELECT COALESCE(country, 'Unknown'), COUNT(*)
		FROM sessions
		WHERE tenant_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
		GROUP BY country
		ORDER BY COUNT(*) DESC
		LIMIT 10
	`, r.tenantID)
	if err != nil {
		return nil, err
	}
	defer rows2.Close()

	for rows2.Next() {
		var cc repository.SessionCountryCount
		if err := rows2.Scan(&cc.Country, &cc.Count); err != nil {
			return nil, err
		}
		stats.ByCountry = append(stats.ByCountry, cc)
	}

	return stats, nil
}

// ─── sharedEmailTokenRepo ────────────────────────────────────────

type sharedEmailTokenRepo struct {
	pool     *pgxpool.Pool
	tenantID uuid.UUID
}

func tableForType(t repository.EmailTokenType) string {
	switch t {
	case repository.EmailTokenPasswordReset:
		return "password_reset_token"
	default:
		return "email_verification_token"
	}
}

func (r *sharedEmailTokenRepo) Create(ctx context.Context, input repository.CreateEmailTokenInput) (*repository.EmailToken, error) {
	table := tableForType(input.Type)
	var token repository.EmailToken

	err := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		// Invalidate previous tokens for same user
		_, err := tx.Exec(ctx,
			fmt.Sprintf(`UPDATE %s SET used_at = NOW() WHERE tenant_id = $1 AND user_id = $2 AND used_at IS NULL`, table),
			r.tenantID, input.UserID)
		if err != nil {
			return err
		}

		expiresAt := time.Now().Add(time.Duration(input.TTLSeconds) * time.Second)
		now := time.Now()

		token = repository.EmailToken{
			TenantID:  r.tenantID.String(),
			UserID:    input.UserID,
			Email:     input.Email,
			Type:      input.Type,
			TokenHash: input.TokenHash,
			ExpiresAt: expiresAt,
			CreatedAt: now,
		}

		query := fmt.Sprintf(`
			INSERT INTO %s (tenant_id, user_id, token_hash, sent_to, expires_at, created_at)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING id
		`, table)
		return tx.QueryRow(ctx, query,
			r.tenantID, input.UserID, input.TokenHash, input.Email, expiresAt, now,
		).Scan(&token.ID)
	})

	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (r *sharedEmailTokenRepo) GetByHash(ctx context.Context, tokenHash string) (*repository.EmailToken, error) {
	for _, t := range []repository.EmailTokenType{repository.EmailTokenVerification, repository.EmailTokenPasswordReset} {
		table := tableForType(t)
		query := fmt.Sprintf(`
			SELECT id, user_id, sent_to, expires_at, used_at, created_at
			FROM %s WHERE tenant_id = $1 AND token_hash = $2
		`, table)
		var token repository.EmailToken
		token.Type = t
		token.TenantID = r.tenantID.String()
		err := r.pool.QueryRow(ctx, query, r.tenantID, tokenHash).Scan(
			&token.ID, &token.UserID, &token.Email,
			&token.ExpiresAt, &token.UsedAt, &token.CreatedAt,
		)
		if err == nil {
			token.TokenHash = tokenHash
			return &token, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}
	return nil, repository.ErrNotFound
}

func (r *sharedEmailTokenRepo) Use(ctx context.Context, tokenHash string) error {
	for _, t := range []repository.EmailTokenType{repository.EmailTokenVerification, repository.EmailTokenPasswordReset} {
		table := tableForType(t)
		var id string
		var useErr error
		useErr = execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
			query := fmt.Sprintf(`
				UPDATE %s SET used_at = NOW()
				WHERE tenant_id = $1 AND token_hash = $2 AND used_at IS NULL AND expires_at > NOW()
				RETURNING id
			`, table)
			return tx.QueryRow(ctx, query, r.tenantID, tokenHash).Scan(&id)
		})
		if useErr == nil {
			return nil // token used successfully
		}
		// Real DB error — return immediately; don't silently try the next table
		if !errors.Is(useErr, pgx.ErrNoRows) {
			return fmt.Errorf("pg_shared: use email token in %s: %w", table, useErr)
		}
		// ErrNoRows = token not found in this table, try next
	}

	// Check if token exists but is expired/used
	for _, t := range []repository.EmailTokenType{repository.EmailTokenVerification, repository.EmailTokenPasswordReset} {
		table := tableForType(t)
		var exists bool
		if err := r.pool.QueryRow(ctx,
			fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM %s WHERE tenant_id = $1 AND token_hash = $2)`, table),
			r.tenantID, tokenHash,
		).Scan(&exists); err != nil {
			return fmt.Errorf("pg_shared: use email token existence check in %s: %w", table, err)
		}
		if exists {
			return repository.ErrTokenExpired
		}
	}
	return repository.ErrNotFound
}

func (r *sharedEmailTokenRepo) DeleteExpired(ctx context.Context) (int, error) {
	var total int
	err := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		for _, t := range []repository.EmailTokenType{repository.EmailTokenVerification, repository.EmailTokenPasswordReset} {
			table := tableForType(t)
			tag, err := tx.Exec(ctx,
				fmt.Sprintf(`DELETE FROM %s WHERE tenant_id = $1 AND (expires_at < NOW() OR used_at IS NOT NULL)`, table),
				r.tenantID)
			if err != nil {
				return err
			}
			total += int(tag.RowsAffected())
		}
		return nil
	})
	return total, err
}
