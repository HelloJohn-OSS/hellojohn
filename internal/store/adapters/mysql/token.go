// Package mysql implementa TokenRepository para MySQL.
package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// Verificar que implementa la interfaz
var _ repository.TokenRepository = (*tokenRepo)(nil)

// Create crea un nuevo refresh token.
func (r *tokenRepo) Create(ctx context.Context, input repository.CreateRefreshTokenInput) (string, error) {
	// MySQL no tiene RETURNING, generamos el UUID en Go
	tokenID := uuid.New().String()

	// Usamos DATE_ADD en lugar de interval de PostgreSQL
	const query = `
		INSERT INTO refresh_token (id, user_id, client_id_text, token_hash, issued_at, expires_at, rotated_from)
		VALUES (?, ?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL ? SECOND), ?)
	`

	_, err := r.db.ExecContext(ctx, query,
		tokenID, input.UserID, input.ClientID, input.TokenHash, input.TTLSeconds, input.RotatedFrom,
	)
	if err != nil {
		return "", fmt.Errorf("mysql: create refresh token: %w", err)
	}

	return tokenID, nil
}

// GetByHash busca un token por su hash.
func (r *tokenRepo) GetByHash(ctx context.Context, tokenHash string) (*repository.RefreshToken, error) {
	const query = `
		SELECT id, user_id, client_id_text, token_hash, issued_at, expires_at, rotated_from, revoked_at
		FROM refresh_token WHERE token_hash = ?
	`

	var token repository.RefreshToken
	var rotatedFrom sql.NullString
	var revokedAtTime sql.NullTime

	err := r.db.QueryRowContext(ctx, query, tokenHash).Scan(
		&token.ID, &token.UserID, &token.ClientID,
		&token.TokenHash, &token.IssuedAt, &token.ExpiresAt,
		&rotatedFrom, &revokedAtTime,
	)
	if err == sql.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("mysql: get token by hash: %w", err)
	}

	token.RotatedFrom = nullStringToPtr(rotatedFrom)
	token.RevokedAt = nullTimeToPtr(revokedAtTime)

	return &token, nil
}

// GetByID obtiene un token por su ID, incluyendo el email del usuario.
func (r *tokenRepo) GetByID(ctx context.Context, tokenID string) (*repository.RefreshToken, error) {
	const query = `
		SELECT t.id, t.user_id, t.client_id_text, t.token_hash, t.issued_at, t.expires_at, 
		       t.rotated_from, t.revoked_at, COALESCE(u.email, '') AS user_email
		FROM refresh_token t
		LEFT JOIN app_user u ON u.id = t.user_id
		WHERE t.id = ?
	`

	var token repository.RefreshToken
	var rotatedFrom sql.NullString
	var revokedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, tokenID).Scan(
		&token.ID, &token.UserID, &token.ClientID,
		&token.TokenHash, &token.IssuedAt, &token.ExpiresAt,
		&rotatedFrom, &revokedAt, &token.UserEmail,
	)
	if err == sql.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("mysql: get token by id: %w", err)
	}

	token.RotatedFrom = nullStringToPtr(rotatedFrom)
	token.RevokedAt = nullTimeToPtr(revokedAt)

	return &token, nil
}

// Revoke revoca un token por su ID.
func (r *tokenRepo) Revoke(ctx context.Context, tokenID string) error {
	const query = `UPDATE refresh_token SET revoked_at = NOW() WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, tokenID)
	return err
}

// GetFamilyRoot returns the root token ID for a refresh rotation family.
func (r *tokenRepo) GetFamilyRoot(ctx context.Context, tokenID string) (string, error) {
	const query = `SELECT rotated_from FROM refresh_token WHERE id = ?`
	current := tokenID

	for i := 0; i < 256; i++ {
		var parent sql.NullString
		err := r.db.QueryRowContext(ctx, query, current).Scan(&parent)
		if err == sql.ErrNoRows {
			return "", repository.ErrNotFound
		}
		if err != nil {
			return "", fmt.Errorf("mysql: get family root: %w", err)
		}
		if !parent.Valid || strings.TrimSpace(parent.String) == "" {
			return current, nil
		}
		current = parent.String
	}

	return "", fmt.Errorf("mysql: refresh token family chain too deep")
}

// RevokeFamily revokes all tokens in the rotation family from a root ID.
func (r *tokenRepo) RevokeFamily(ctx context.Context, familyRootID string) error {
	seen := map[string]struct{}{}
	queue := []string{familyRootID}
	ids := make([]string, 0, 8)

	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)

		rows, err := r.db.QueryContext(ctx, `SELECT id FROM refresh_token WHERE rotated_from = ?`, id)
		if err != nil {
			return fmt.Errorf("mysql: revoke family list children: %w", err)
		}
		for rows.Next() {
			var child string
			if err := rows.Scan(&child); err != nil {
				_ = rows.Close()
				return fmt.Errorf("mysql: revoke family scan child: %w", err)
			}
			queue = append(queue, child)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return fmt.Errorf("mysql: revoke family iterate children: %w", err)
		}
		_ = rows.Close()
	}

	if len(ids) == 0 {
		return nil
	}

	placeholders := strings.TrimRight(strings.Repeat("?,", len(ids)), ",")
	query := `UPDATE refresh_token SET revoked_at = NOW() WHERE revoked_at IS NULL AND id IN (` + placeholders + `)`
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}

	if _, err := r.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("mysql: revoke family update: %w", err)
	}
	return nil
}

// RevokeAllByUser revoca todos los tokens de un usuario.
func (r *tokenRepo) RevokeAllByUser(ctx context.Context, userID, clientID string) (int, error) {
	var query string
	var args []any

	if clientID != "" {
		query = `UPDATE refresh_token SET revoked_at = NOW() WHERE user_id = ? AND client_id_text = ? AND revoked_at IS NULL`
		args = []any{userID, clientID}
	} else {
		query = `UPDATE refresh_token SET revoked_at = NOW() WHERE user_id = ? AND revoked_at IS NULL`
		args = []any{userID}
	}

	result, err := r.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}

	rowsAffected, _ := result.RowsAffected()
	return int(rowsAffected), nil
}

// RevokeAllByClient revoca todos los tokens de un cliente.
func (r *tokenRepo) RevokeAllByClient(ctx context.Context, clientID string) error {
	const query = `UPDATE refresh_token SET revoked_at = NOW() WHERE client_id_text = ? AND revoked_at IS NULL`
	_, err := r.db.ExecContext(ctx, query, clientID)
	return err
}

// List lista tokens con filtros y paginación.
func (r *tokenRepo) List(ctx context.Context, filter repository.ListTokensFilter) ([]repository.RefreshToken, error) {
	// Validate pagination
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

	// Build query dynamically
	query := `
		SELECT t.id, t.user_id, t.client_id_text, t.token_hash, t.issued_at, t.expires_at, 
		       t.rotated_from, t.revoked_at, COALESCE(u.email, '') AS user_email
		FROM refresh_token t
		LEFT JOIN app_user u ON u.id = t.user_id
		WHERE 1=1
	`
	args := []any{}

	// Filter by user_id
	if filter.UserID != nil && *filter.UserID != "" {
		query += " AND t.user_id = ?"
		args = append(args, *filter.UserID)
	}

	// Filter by client_id
	if filter.ClientID != nil && *filter.ClientID != "" {
		query += " AND t.client_id_text = ?"
		args = append(args, *filter.ClientID)
	}

	// Filter by status
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

	// Filter by search (email) - MySQL uses LIKE instead of ILIKE
	if filter.Search != nil && *filter.Search != "" {
		query += " AND u.email LIKE ?"
		args = append(args, "%"+*filter.Search+"%")
	}

	// Order and paginate
	query += " ORDER BY t.issued_at DESC LIMIT ? OFFSET ?"
	args = append(args, filter.PageSize, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("mysql: list tokens: %w", err)
	}
	defer rows.Close()

	var tokens []repository.RefreshToken
	for rows.Next() {
		var token repository.RefreshToken
		var rotatedFrom sql.NullString
		var revokedAt sql.NullTime

		if err := rows.Scan(
			&token.ID, &token.UserID, &token.ClientID,
			&token.TokenHash, &token.IssuedAt, &token.ExpiresAt,
			&rotatedFrom, &revokedAt, &token.UserEmail,
		); err != nil {
			return nil, fmt.Errorf("mysql: scan token: %w", err)
		}

		token.RotatedFrom = nullStringToPtr(rotatedFrom)
		token.RevokedAt = nullTimeToPtr(revokedAt)
		tokens = append(tokens, token)
	}

	return tokens, rows.Err()
}

// Count cuenta tokens con filtros.
func (r *tokenRepo) Count(ctx context.Context, filter repository.ListTokensFilter) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM refresh_token t
		LEFT JOIN app_user u ON u.id = t.user_id
		WHERE 1=1
	`
	args := []any{}

	if filter.UserID != nil && *filter.UserID != "" {
		query += " AND t.user_id = ?"
		args = append(args, *filter.UserID)
	}

	if filter.ClientID != nil && *filter.ClientID != "" {
		query += " AND t.client_id_text = ?"
		args = append(args, *filter.ClientID)
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
		query += " AND u.email LIKE ?"
		args = append(args, "%"+*filter.Search+"%")
	}

	var count int
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	return count, err
}

// RevokeAll revoca todos los tokens activos.
func (r *tokenRepo) RevokeAll(ctx context.Context) (int, error) {
	const query = `UPDATE refresh_token SET revoked_at = NOW() WHERE revoked_at IS NULL`
	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, err
	}
	rowsAffected, _ := result.RowsAffected()
	return int(rowsAffected), nil
}

// GetStats obtiene estadísticas de tokens.
func (r *tokenRepo) GetStats(ctx context.Context) (*repository.TokenStats, error) {
	stats := &repository.TokenStats{}

	// Total activos
	err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM refresh_token 
		WHERE revoked_at IS NULL AND expires_at > NOW()
	`).Scan(&stats.TotalActive)
	if err != nil {
		return nil, fmt.Errorf("mysql: count active tokens: %w", err)
	}

	// Emitidos hoy
	err = r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM refresh_token 
		WHERE issued_at >= CURDATE()
	`).Scan(&stats.IssuedToday)
	if err != nil {
		return nil, fmt.Errorf("mysql: count issued today: %w", err)
	}

	// Revocados hoy
	err = r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM refresh_token 
		WHERE revoked_at >= CURDATE()
	`).Scan(&stats.RevokedToday)
	if err != nil {
		return nil, fmt.Errorf("mysql: count revoked today: %w", err)
	}

	// Tiempo de vida promedio (en horas)
	// MySQL usa TIMESTAMPDIFF en lugar de EXTRACT(EPOCH FROM ...)
	err = r.db.QueryRowContext(ctx, `
		SELECT COALESCE(
			AVG(TIMESTAMPDIFF(SECOND, issued_at, 
				COALESCE(revoked_at, LEAST(expires_at, NOW()))
			) / 3600.0), 0
		)
		FROM refresh_token 
		WHERE revoked_at IS NOT NULL OR expires_at <= NOW()
	`).Scan(&stats.AvgLifetimeHours)
	if err != nil {
		return nil, fmt.Errorf("mysql: avg lifetime: %w", err)
	}

	// Por client (top 10)
	rows, err := r.db.QueryContext(ctx, `
		SELECT client_id_text, COUNT(*) as cnt
		FROM refresh_token
		WHERE revoked_at IS NULL AND expires_at > NOW()
		GROUP BY client_id_text
		ORDER BY cnt DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, fmt.Errorf("mysql: tokens by client: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var cc repository.ClientTokenCount
		if err := rows.Scan(&cc.ClientID, &cc.Count); err != nil {
			return nil, fmt.Errorf("mysql: scan client count: %w", err)
		}
		stats.ByClient = append(stats.ByClient, cc)
	}

	return stats, rows.Err()
}

// buildWhereClause construye una cláusula WHERE dinámica.
func buildWhereClause(conditions []string) string {
	if len(conditions) == 0 {
		return "1=1"
	}
	return strings.Join(conditions, " AND ")
}
