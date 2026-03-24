package mysql_shared

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// ─── sharedIdentityRepo ──────────────────────────────────────────

type sharedIdentityRepo struct {
	db       *sql.DB
	tenantID uuid.UUID
}

func (r *sharedIdentityRepo) GetByProvider(ctx context.Context, _ string, provider, providerUserID string) (*repository.SocialIdentity, error) {
	const query = `
		SELECT id, user_id, provider, provider_user_id, email, email_verified, data, created_at, updated_at
		FROM identity
		WHERE tenant_id = ? AND provider = ? AND provider_user_id = ?
	`
	var identity repository.SocialIdentity
	var data []byte
	err := r.db.QueryRowContext(ctx, query, r.tenantID.String(), provider, providerUserID).Scan(
		&identity.ID, &identity.UserID, &identity.Provider, &identity.ProviderUserID,
		&identity.Email, &identity.EmailVerified, &data,
		&identity.CreatedAt, &identity.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	identity.TenantID = r.tenantID.String()
	return &identity, nil
}

func (r *sharedIdentityRepo) GetByUserID(ctx context.Context, userID string) ([]repository.SocialIdentity, error) {
	const query = `
		SELECT id, user_id, provider, provider_user_id, email, email_verified, data, created_at, updated_at
		FROM identity WHERE tenant_id = ? AND user_id = ? ORDER BY created_at
	`
	rows, err := r.db.QueryContext(ctx, query, r.tenantID.String(), userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var identities []repository.SocialIdentity
	for rows.Next() {
		var identity repository.SocialIdentity
		var data []byte
		if err := rows.Scan(
			&identity.ID, &identity.UserID, &identity.Provider, &identity.ProviderUserID,
			&identity.Email, &identity.EmailVerified, &data,
			&identity.CreatedAt, &identity.UpdatedAt,
		); err != nil {
			return nil, err
		}
		identity.TenantID = r.tenantID.String()
		identities = append(identities, identity)
	}
	return identities, rows.Err()
}

func (r *sharedIdentityRepo) Upsert(ctx context.Context, input repository.UpsertSocialIdentityInput) (userID string, isNew bool, err error) {
	tx, txErr := r.db.BeginTx(ctx, nil)
	if txErr != nil {
		return "", false, fmt.Errorf("mysql_shared: begin tx: %w", txErr)
	}
	defer tx.Rollback()

	// 1. Find existing identity
	var existingIdentityUserID string
	scanErr := tx.QueryRowContext(ctx,
		`SELECT user_id FROM identity WHERE tenant_id = ? AND provider = ? AND provider_user_id = ?`,
		r.tenantID.String(), input.Provider, input.ProviderUserID,
	).Scan(&existingIdentityUserID)

	if scanErr == nil {
		// Identity exists -> update and return
		_, updateErr := tx.ExecContext(ctx, `
			UPDATE identity SET email = ?, email_verified = ?, updated_at = NOW(6)
			WHERE tenant_id = ? AND provider = ? AND provider_user_id = ?`,
			input.Email, input.EmailVerified,
			r.tenantID.String(), input.Provider, input.ProviderUserID,
		)
		if updateErr != nil {
			return "", false, updateErr
		}
		if cErr := tx.Commit(); cErr != nil {
			return "", false, cErr
		}
		return existingIdentityUserID, false, nil
	} else if !errors.Is(scanErr, sql.ErrNoRows) {
		return "", false, scanErr
	}

	// 2. Identity doesn't exist. Find user by email.
	var existingUserID string
	scanErr = tx.QueryRowContext(ctx,
		`SELECT id FROM app_user WHERE tenant_id = ? AND email = ?`,
		r.tenantID.String(), input.Email,
	).Scan(&existingUserID)

	if scanErr == nil {
		userID = existingUserID
		isNew = false
	} else if errors.Is(scanErr, sql.ErrNoRows) {
		// User doesn't exist -> create new
		userID = uuid.NewString()
		isNew = true
		now := time.Now()
		_, createErr := tx.ExecContext(ctx, `
			INSERT INTO app_user (id, tenant_id, email, email_verified, name, picture, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			userID, r.tenantID.String(), input.Email, input.EmailVerified, input.Name, input.Picture, now, now,
		)
		if createErr != nil {
			return "", false, createErr
		}
	} else {
		return "", false, scanErr
	}

	// 3. Create identity
	identityID := uuid.NewString()
	now := time.Now()
	_, insertErr := tx.ExecContext(ctx, `
		INSERT INTO identity (id, tenant_id, user_id, provider, provider_user_id, email, email_verified, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		identityID, r.tenantID.String(), userID, input.Provider, input.ProviderUserID,
		input.Email, input.EmailVerified, now, now,
	)
	if insertErr != nil {
		return "", false, insertErr
	}

	if cErr := tx.Commit(); cErr != nil {
		return "", false, cErr
	}
	return userID, isNew, nil
}

func (r *sharedIdentityRepo) Link(ctx context.Context, userID string, input repository.UpsertSocialIdentityInput) (*repository.SocialIdentity, error) {
	identityID := uuid.NewString()
	now := time.Now()

	identity := &repository.SocialIdentity{
		ID:             identityID,
		UserID:         userID,
		TenantID:       r.tenantID.String(),
		Provider:       input.Provider,
		ProviderUserID: input.ProviderUserID,
		Email:          input.Email,
		EmailVerified:  input.EmailVerified,
		Name:           input.Name,
		Picture:        input.Picture,
		RawClaims:      input.RawClaims,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
		INSERT INTO identity (id, tenant_id, user_id, provider, provider_user_id, email, email_verified, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		identityID, r.tenantID.String(), userID, input.Provider, input.ProviderUserID,
		input.Email, input.EmailVerified, now, now,
	)
	if err != nil {
		return nil, err
	}
	if cErr := tx.Commit(); cErr != nil {
		return nil, cErr
	}
	return identity, nil
}

func (r *sharedIdentityRepo) Unlink(ctx context.Context, userID, provider string) error {
	// Prevent unlinking last identity
	var cnt int
	err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM identity WHERE tenant_id = ? AND user_id = ?`, r.tenantID.String(), userID,
	).Scan(&cnt)
	if err != nil {
		return err
	}
	if cnt <= 1 {
		return repository.ErrLastIdentity
	}

	tx, txErr := r.db.BeginTx(ctx, nil)
	if txErr != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", txErr)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`DELETE FROM identity WHERE tenant_id = ? AND user_id = ? AND provider = ?`,
		r.tenantID.String(), userID, provider,
	)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *sharedIdentityRepo) UpdateClaims(ctx context.Context, identityID string, claims map[string]any) error {
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return fmt.Errorf("mysql_shared: marshal claims: %w", err)
	}

	tx, txErr := r.db.BeginTx(ctx, nil)
	if txErr != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", txErr)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		`UPDATE identity SET data = ?, updated_at = NOW(6) WHERE tenant_id = ? AND id = ?`,
		claimsJSON, r.tenantID.String(), identityID,
	)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return repository.ErrNotFound
	}
	return tx.Commit()
}

// ─── sharedTokenRepo ──────────────────────────────────────────────

type sharedTokenRepo struct {
	db       *sql.DB
	tenantID uuid.UUID
}

func (r *sharedTokenRepo) Create(ctx context.Context, input repository.CreateRefreshTokenInput) (string, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	id := uuid.NewString()
	const query = `
		INSERT INTO refresh_token (id, tenant_id, user_id, client_id_text, token_hash, issued_at, expires_at, rotated_from)
		VALUES (?, ?, ?, ?, ?, NOW(6), DATE_ADD(NOW(6), INTERVAL ? SECOND), ?)
	`
	_, err = tx.ExecContext(ctx, query,
		id, r.tenantID.String(), input.UserID, input.ClientID, input.TokenHash, input.TTLSeconds, input.RotatedFrom,
	)
	if err != nil {
		return "", err
	}
	if cErr := tx.Commit(); cErr != nil {
		return "", cErr
	}
	return id, nil
}

func (r *sharedTokenRepo) GetByHash(ctx context.Context, tokenHash string) (*repository.RefreshToken, error) {
	const query = `
		SELECT id, user_id, client_id_text, token_hash, issued_at, expires_at, rotated_from, revoked_at
		FROM refresh_token WHERE tenant_id = ? AND token_hash = ?
	`
	var token repository.RefreshToken
	err := r.db.QueryRowContext(ctx, query, r.tenantID.String(), tokenHash).Scan(
		&token.ID, &token.UserID, &token.ClientID,
		&token.TokenHash, &token.IssuedAt, &token.ExpiresAt, &token.RotatedFrom, &token.RevokedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: GetByHash: %w", err)
	}
	token.TenantID = r.tenantID.String()
	return &token, nil
}

func (r *sharedTokenRepo) Revoke(ctx context.Context, tokenID string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		`UPDATE refresh_token SET revoked_at = NOW(6) WHERE tenant_id = ? AND id = ?`,
		r.tenantID.String(), tokenID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return repository.ErrNotFound
	}
	return tx.Commit()
}

func (r *sharedTokenRepo) GetFamilyRoot(ctx context.Context, tokenID string) (string, error) {
	// MySQL 8.0+ supports recursive CTEs
	const query = `
		WITH RECURSIVE chain AS (
			SELECT id, rotated_from
			FROM refresh_token
			WHERE tenant_id = ? AND id = ?
			UNION ALL
			SELECT rt.id, rt.rotated_from
			FROM refresh_token rt
			INNER JOIN chain c ON rt.id = c.rotated_from
			WHERE rt.tenant_id = ?
		)
		SELECT id FROM chain WHERE rotated_from IS NULL
		LIMIT 1
	`
	var rootID string
	if err := r.db.QueryRowContext(ctx, query, r.tenantID.String(), tokenID, r.tenantID.String()).Scan(&rootID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", repository.ErrNotFound
		}
		return "", fmt.Errorf("mysql_shared: GetFamilyRoot: %w", err)
	}
	return rootID, nil
}

func (r *sharedTokenRepo) RevokeFamily(ctx context.Context, familyRootID string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	// MySQL doesn't support UPDATE ... WHERE id IN (recursive CTE) directly in some versions.
	// Use a temp table approach: collect IDs first, then update.
	const collectQuery = `
		WITH RECURSIVE family AS (
			SELECT id FROM refresh_token WHERE tenant_id = ? AND id = ?
			UNION ALL
			SELECT rt.id
			FROM refresh_token rt
			INNER JOIN family f ON rt.rotated_from = f.id
			WHERE rt.tenant_id = ?
		)
		SELECT id FROM family
	`
	rows, err := tx.QueryContext(ctx, collectQuery, r.tenantID.String(), familyRootID, r.tenantID.String())
	if err != nil {
		return err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if len(ids) > 0 {
		placeholders := make([]string, len(ids))
		args := []any{r.tenantID.String()}
		for i, id := range ids {
			placeholders[i] = "?"
			args = append(args, id)
		}
		_, err = tx.ExecContext(ctx,
			fmt.Sprintf(`UPDATE refresh_token SET revoked_at = NOW(6) WHERE tenant_id = ? AND id IN (%s) AND revoked_at IS NULL`,
				strings.Join(placeholders, ",")),
			args...,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (r *sharedTokenRepo) RevokeAllByUser(ctx context.Context, userID, clientID string) (int, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	var query string
	var args []any
	if clientID != "" {
		query = `UPDATE refresh_token SET revoked_at = NOW(6) WHERE tenant_id = ? AND user_id = ? AND client_id_text = ? AND revoked_at IS NULL`
		args = []any{r.tenantID.String(), userID, clientID}
	} else {
		query = `UPDATE refresh_token SET revoked_at = NOW(6) WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL`
		args = []any{r.tenantID.String(), userID}
	}
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	count, _ := result.RowsAffected()
	if cErr := tx.Commit(); cErr != nil {
		return 0, cErr
	}
	return int(count), nil
}

func (r *sharedTokenRepo) RevokeAllByClient(ctx context.Context, clientID string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		`UPDATE refresh_token SET revoked_at = NOW(6) WHERE tenant_id = ? AND client_id_text = ? AND revoked_at IS NULL`,
		r.tenantID.String(), clientID)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *sharedTokenRepo) GetByID(ctx context.Context, tokenID string) (*repository.RefreshToken, error) {
	const query = `
		SELECT t.id, t.user_id, t.client_id_text, t.token_hash, t.issued_at, t.expires_at, t.rotated_from, t.revoked_at,
		       COALESCE(u.email, '') AS user_email
		FROM refresh_token t
		LEFT JOIN app_user u ON u.id = t.user_id AND u.tenant_id = ?
		WHERE t.tenant_id = ? AND t.id = ?
	`
	var token repository.RefreshToken
	err := r.db.QueryRowContext(ctx, query, r.tenantID.String(), r.tenantID.String(), tokenID).Scan(
		&token.ID, &token.UserID, &token.ClientID,
		&token.TokenHash, &token.IssuedAt, &token.ExpiresAt, &token.RotatedFrom, &token.RevokedAt,
		&token.UserEmail,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: GetByID: %w", err)
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
		LEFT JOIN app_user u ON u.id = t.user_id AND u.tenant_id = ?
		WHERE t.tenant_id = ?
	`
	args := []any{r.tenantID.String(), r.tenantID.String()}

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
			query += " AND t.revoked_at IS NULL AND t.expires_at > NOW(6)"
		case "expired":
			query += " AND t.revoked_at IS NULL AND t.expires_at <= NOW(6)"
		case "revoked":
			query += " AND t.revoked_at IS NOT NULL"
		}
	}
	if filter.Search != nil && *filter.Search != "" {
		query += " AND u.email LIKE ?"
		args = append(args, "%"+*filter.Search+"%")
	}

	query += " ORDER BY t.issued_at DESC LIMIT ? OFFSET ?"
	args = append(args, filter.PageSize, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
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
		LEFT JOIN app_user u ON u.id = t.user_id AND u.tenant_id = ?
		WHERE t.tenant_id = ?
	`
	args := []any{r.tenantID.String(), r.tenantID.String()}

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
			query += " AND t.revoked_at IS NULL AND t.expires_at > NOW(6)"
		case "expired":
			query += " AND t.revoked_at IS NULL AND t.expires_at <= NOW(6)"
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

func (r *sharedTokenRepo) RevokeAll(ctx context.Context) (int, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		`UPDATE refresh_token SET revoked_at = NOW(6) WHERE tenant_id = ? AND revoked_at IS NULL`,
		r.tenantID.String())
	if err != nil {
		return 0, err
	}
	count, _ := result.RowsAffected()
	if cErr := tx.Commit(); cErr != nil {
		return 0, cErr
	}
	return int(count), nil
}

func (r *sharedTokenRepo) GetStats(ctx context.Context) (*repository.TokenStats, error) {
	stats := &repository.TokenStats{}

	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM refresh_token
		WHERE tenant_id = ? AND revoked_at IS NULL AND expires_at > NOW(6)
	`, r.tenantID.String()).Scan(&stats.TotalActive); err != nil {
		return nil, fmt.Errorf("GetStats TotalActive: %w", err)
	}

	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM refresh_token
		WHERE tenant_id = ? AND issued_at >= CURDATE()
	`, r.tenantID.String()).Scan(&stats.IssuedToday); err != nil {
		return nil, fmt.Errorf("GetStats IssuedToday: %w", err)
	}

	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM refresh_token
		WHERE tenant_id = ? AND revoked_at >= CURDATE()
	`, r.tenantID.String()).Scan(&stats.RevokedToday); err != nil {
		return nil, fmt.Errorf("GetStats RevokedToday: %w", err)
	}

	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(
			AVG(TIMESTAMPDIFF(SECOND, issued_at, COALESCE(revoked_at, LEAST(expires_at, NOW(6)))) / 3600.0), 0
		)
		FROM refresh_token
		WHERE tenant_id = ? AND (revoked_at IS NOT NULL OR expires_at <= NOW(6))
	`, r.tenantID.String()).Scan(&stats.AvgLifetimeHours); err != nil {
		return nil, fmt.Errorf("GetStats AvgLifetimeHours: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT client_id_text, COUNT(*) as cnt
		FROM refresh_token
		WHERE tenant_id = ? AND revoked_at IS NULL AND expires_at > NOW(6)
		GROUP BY client_id_text
		ORDER BY cnt DESC
		LIMIT 10
	`, r.tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("GetStats ByClient query: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var cc repository.ClientTokenCount
		if err := rows.Scan(&cc.ClientID, &cc.Count); err != nil {
			return nil, err
		}
		stats.ByClient = append(stats.ByClient, cc)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	_ = tx.Commit()
	return stats, nil
}

// ─── sharedEmailTokenRepo ────────────────────────────────────────

type sharedEmailTokenRepo struct {
	db       *sql.DB
	tenantID uuid.UUID
}

func mysqlTableForType(t repository.EmailTokenType) string {
	switch t {
	case repository.EmailTokenPasswordReset:
		return "password_reset_token"
	default:
		return "email_verification_token"
	}
}

func (r *sharedEmailTokenRepo) Create(ctx context.Context, input repository.CreateEmailTokenInput) (*repository.EmailToken, error) {
	table := mysqlTableForType(input.Type)
	var token repository.EmailToken

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	// Invalidate previous tokens for same user
	_, err = tx.ExecContext(ctx,
		fmt.Sprintf(`UPDATE %s SET used_at = NOW(6) WHERE tenant_id = ? AND user_id = ? AND used_at IS NULL`, table),
		r.tenantID.String(), input.UserID)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(time.Duration(input.TTLSeconds) * time.Second)
	now := time.Now()
	tokenID := uuid.NewString()

	token = repository.EmailToken{
		ID:        tokenID,
		TenantID:  r.tenantID.String(),
		UserID:    input.UserID,
		Email:     input.Email,
		Type:      input.Type,
		TokenHash: input.TokenHash,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}

	query := fmt.Sprintf(`
		INSERT INTO %s (id, tenant_id, user_id, token_hash, sent_to, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, table)
	_, err = tx.ExecContext(ctx, query,
		tokenID, r.tenantID.String(), input.UserID, input.TokenHash, input.Email, expiresAt, now,
	)
	if err != nil {
		return nil, err
	}

	if cErr := tx.Commit(); cErr != nil {
		return nil, cErr
	}
	return &token, nil
}

func (r *sharedEmailTokenRepo) GetByHash(ctx context.Context, tokenHash string) (*repository.EmailToken, error) {
	for _, t := range []repository.EmailTokenType{repository.EmailTokenVerification, repository.EmailTokenPasswordReset} {
		table := mysqlTableForType(t)
		query := fmt.Sprintf(`
			SELECT id, user_id, sent_to, expires_at, used_at, created_at
			FROM %s WHERE tenant_id = ? AND token_hash = ?
		`, table)
		var token repository.EmailToken
		token.Type = t
		token.TenantID = r.tenantID.String()
		err := r.db.QueryRowContext(ctx, query, r.tenantID.String(), tokenHash).Scan(
			&token.ID, &token.UserID, &token.Email,
			&token.ExpiresAt, &token.UsedAt, &token.CreatedAt,
		)
		if err == nil {
			token.TokenHash = tokenHash
			return &token, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}
	return nil, repository.ErrNotFound
}

func (r *sharedEmailTokenRepo) Use(ctx context.Context, tokenHash string) error {
	for _, t := range []repository.EmailTokenType{repository.EmailTokenVerification, repository.EmailTokenPasswordReset} {
		table := mysqlTableForType(t)

		tx, txErr := r.db.BeginTx(ctx, nil)
		if txErr != nil {
			return fmt.Errorf("mysql_shared: begin tx: %w", txErr)
		}

		query := fmt.Sprintf(`
			UPDATE %s SET used_at = NOW(6)
			WHERE tenant_id = ? AND token_hash = ? AND used_at IS NULL AND expires_at > NOW(6)
		`, table)
		result, err := tx.ExecContext(ctx, query, r.tenantID.String(), tokenHash)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("mysql_shared: use email token in %s: %w", table, err)
		}
		rows, _ := result.RowsAffected()
		if rows > 0 {
			return tx.Commit()
		}
		tx.Rollback()
	}

	// Check if token exists but is expired/used
	for _, t := range []repository.EmailTokenType{repository.EmailTokenVerification, repository.EmailTokenPasswordReset} {
		table := mysqlTableForType(t)
		var exists bool
		if err := r.db.QueryRowContext(ctx,
			fmt.Sprintf(`SELECT EXISTS(SELECT 1 FROM %s WHERE tenant_id = ? AND token_hash = ?)`, table),
			r.tenantID.String(), tokenHash,
		).Scan(&exists); err != nil {
			return fmt.Errorf("mysql_shared: use email token existence check in %s: %w", table, err)
		}
		if exists {
			return repository.ErrTokenExpired
		}
	}
	return repository.ErrNotFound
}

func (r *sharedEmailTokenRepo) DeleteExpired(ctx context.Context) (int, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	var total int
	for _, t := range []repository.EmailTokenType{repository.EmailTokenVerification, repository.EmailTokenPasswordReset} {
		table := mysqlTableForType(t)
		result, err := tx.ExecContext(ctx,
			fmt.Sprintf(`DELETE FROM %s WHERE tenant_id = ? AND (expires_at < NOW(6) OR used_at IS NOT NULL)`, table),
			r.tenantID.String())
		if err != nil {
			return 0, err
		}
		rows, _ := result.RowsAffected()
		total += int(rows)
	}

	if cErr := tx.Commit(); cErr != nil {
		return 0, cErr
	}
	return total, nil
}

// ─── sharedSessionRepo ──────────────────────────────────────────

type sharedSessionRepo struct {
	db       *sql.DB
	tenantID uuid.UUID
}

func (r *sharedSessionRepo) Create(ctx context.Context, input repository.CreateSessionInput) (*repository.Session, error) {
	tid := r.tenantID.String()
	const insertQ = `
		INSERT INTO sessions (
			tenant_id, user_id, session_id_hash, ip_address, user_agent,
			device_type, browser, os, country_code, country, city,
			expires_at, created_at, last_activity
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
	`
	res, err := r.db.ExecContext(ctx, insertQ,
		tid, input.UserID, input.SessionIDHash,
		nullIfEmpty(input.IPAddress), nullIfEmpty(input.UserAgent),
		nullIfEmpty(input.DeviceType), nullIfEmpty(input.Browser),
		nullIfEmpty(input.OS), nullIfEmpty(input.CountryCode),
		nullIfEmpty(input.Country), nullIfEmpty(input.City),
		input.ExpiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: create session: %w", err)
	}

	lastID, _ := res.LastInsertId()

	var s repository.Session
	const selQ = `
		SELECT id, user_id, session_id_hash, ip_address, user_agent,
			device_type, browser, os, country_code, country, city,
			created_at, last_activity, expires_at, revoked_at, revoked_by, revoke_reason
		FROM sessions WHERE id = ? AND tenant_id = ?
	`
	err = r.db.QueryRowContext(ctx, selQ, lastID, tid).Scan(
		&s.ID, &s.UserID, &s.SessionIDHash, &s.IPAddress, &s.UserAgent,
		&s.DeviceType, &s.Browser, &s.OS, &s.CountryCode, &s.Country, &s.City,
		&s.CreatedAt, &s.LastActivity, &s.ExpiresAt, &s.RevokedAt, &s.RevokedBy, &s.RevokeReason,
	)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: read-back session: %w", err)
	}
	return &s, nil
}

func (r *sharedSessionRepo) Get(ctx context.Context, sessionIDHash string) (*repository.Session, error) {
	const query = `
		SELECT id, user_id, session_id_hash, ip_address, user_agent,
			device_type, browser, os, country_code, country, city,
			created_at, last_activity, expires_at, revoked_at, revoked_by, revoke_reason
		FROM sessions
		WHERE tenant_id = ? AND session_id_hash = ?
	`
	var s repository.Session
	err := r.db.QueryRowContext(ctx, query, r.tenantID.String(), sessionIDHash).Scan(
		&s.ID, &s.UserID, &s.SessionIDHash, &s.IPAddress, &s.UserAgent,
		&s.DeviceType, &s.Browser, &s.OS, &s.CountryCode, &s.Country, &s.City,
		&s.CreatedAt, &s.LastActivity, &s.ExpiresAt, &s.RevokedAt, &s.RevokedBy, &s.RevokeReason,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: get session: %w", err)
	}
	return &s, nil
}

func (r *sharedSessionRepo) GetByIDHash(ctx context.Context, sessionIDHash string) (*repository.Session, error) {
	return r.Get(ctx, sessionIDHash)
}

func (r *sharedSessionRepo) UpdateActivity(ctx context.Context, sessionIDHash string, lastActivity time.Time) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE sessions SET last_activity = ? WHERE tenant_id = ? AND session_id_hash = ?`,
		lastActivity, r.tenantID.String(), sessionIDHash)
	return err
}

func (r *sharedSessionRepo) List(ctx context.Context, filter repository.ListSessionsFilter) ([]repository.Session, int, error) {
	tid := r.tenantID.String()
	where := []string{"tenant_id = ?"}
	args := []any{tid}

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
		where = append(where, "(ip_address LIKE ? OR city LIKE ? OR country LIKE ?)")
		pat := "%" + *filter.Search + "%"
		args = append(args, pat, pat, pat)
	}

	whereClause := strings.Join(where, " AND ")

	var total int
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	if err := r.db.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM sessions WHERE %s", whereClause), countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("mysql_shared: count sessions: %w", err)
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
		LIMIT ? OFFSET ?
	`, whereClause)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("mysql_shared: list sessions: %w", err)
	}
	defer rows.Close()

	var sessions []repository.Session
	for rows.Next() {
		var s repository.Session
		if err := rows.Scan(
			&s.ID, &s.UserID, &s.SessionIDHash, &s.IPAddress, &s.UserAgent,
			&s.DeviceType, &s.Browser, &s.OS, &s.CountryCode, &s.Country, &s.City,
			&s.CreatedAt, &s.LastActivity, &s.ExpiresAt, &s.RevokedAt, &s.RevokedBy, &s.RevokeReason,
		); err != nil {
			return nil, 0, fmt.Errorf("mysql_shared: scan session: %w", err)
		}
		sessions = append(sessions, s)
	}
	return sessions, total, nil
}

func (r *sharedSessionRepo) Revoke(ctx context.Context, sessionIDHash, revokedBy, reason string) error {
	tid := r.tenantID.String()
	res, err := r.db.ExecContext(ctx, `
		UPDATE sessions
		SET revoked_at = NOW(), revoked_by = ?, revoke_reason = ?
		WHERE tenant_id = ? AND session_id_hash = ? AND revoked_at IS NULL
	`, revokedBy, reason, tid, sessionIDHash)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return repository.ErrNotFound
	}
	return nil
}

func (r *sharedSessionRepo) RevokeAllByUser(ctx context.Context, userID, revokedBy, reason string) (int, error) {
	tid := r.tenantID.String()
	res, err := r.db.ExecContext(ctx, `
		UPDATE sessions
		SET revoked_at = NOW(), revoked_by = ?, revoke_reason = ?
		WHERE tenant_id = ? AND user_id = ? AND revoked_at IS NULL AND expires_at > NOW()
	`, revokedBy, reason, tid, userID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (r *sharedSessionRepo) RevokeAll(ctx context.Context, revokedBy, reason string) (int, error) {
	tid := r.tenantID.String()
	res, err := r.db.ExecContext(ctx, `
		UPDATE sessions
		SET revoked_at = NOW(), revoked_by = ?, revoke_reason = ?
		WHERE tenant_id = ? AND revoked_at IS NULL AND expires_at > NOW()
	`, revokedBy, reason, tid)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (r *sharedSessionRepo) DeleteExpired(ctx context.Context) (int, error) {
	tid := r.tenantID.String()
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE tenant_id = ? AND (expires_at < NOW() OR revoked_at IS NOT NULL)`,
		tid)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (r *sharedSessionRepo) GetStats(ctx context.Context) (*repository.SessionStats, error) {
	tid := r.tenantID.String()
	stats := &repository.SessionStats{}

	if err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sessions WHERE tenant_id = ? AND revoked_at IS NULL AND expires_at > NOW()`,
		tid).Scan(&stats.TotalActive); err != nil {
		return nil, err
	}

	if err := r.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sessions WHERE tenant_id = ? AND created_at >= CURDATE()`,
		tid).Scan(&stats.TotalToday); err != nil {
		return nil, err
	}

	devRows, err := r.db.QueryContext(ctx, `
		SELECT COALESCE(device_type, 'unknown'), COUNT(*)
		FROM sessions
		WHERE tenant_id = ? AND revoked_at IS NULL AND expires_at > NOW()
		GROUP BY device_type
	`, tid)
	if err != nil {
		return nil, err
	}
	defer devRows.Close()
	for devRows.Next() {
		var dc repository.SessionDeviceCount
		if err := devRows.Scan(&dc.DeviceType, &dc.Count); err != nil {
			return nil, err
		}
		stats.ByDevice = append(stats.ByDevice, dc)
	}

	countryRows, err := r.db.QueryContext(ctx, `
		SELECT COALESCE(country, 'Unknown'), COUNT(*)
		FROM sessions
		WHERE tenant_id = ? AND revoked_at IS NULL AND expires_at > NOW()
		GROUP BY country
		ORDER BY COUNT(*) DESC
		LIMIT 10
	`, tid)
	if err != nil {
		return nil, err
	}
	defer countryRows.Close()
	for countryRows.Next() {
		var cc repository.SessionCountryCount
		if err := countryRows.Scan(&cc.Country, &cc.Count); err != nil {
			return nil, err
		}
		stats.ByCountry = append(stats.ByCountry, cc)
	}

	return stats, nil
}
