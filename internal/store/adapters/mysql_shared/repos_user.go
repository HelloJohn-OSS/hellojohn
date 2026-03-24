package mysql_shared

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	secpassword "github.com/dropDatabas3/hellojohn/internal/security/password"
)

// ─── sharedUserRepo ───────────────────────────────────────────────

// sharedUserRepo implements repository.UserRepository for Global Data Plane (MySQL).
// ALL queries include WHERE tenant_id = ? as the sole tenant isolation mechanism.
// NO RLS — MySQL doesn't support it.
type sharedUserRepo struct {
	db       *sql.DB
	tenantID uuid.UUID
}

// sharedUnmarshalCustomData deserializes the custom_data JSON column into a map.
// Returns an empty (non-nil) map on NULL or invalid JSON.
func sharedUnmarshalCustomData(data []byte) map[string]any {
	result := make(map[string]any)
	if len(data) == 0 {
		return result
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return make(map[string]any)
	}
	return result
}

func (r *sharedUserRepo) GetByEmail(ctx context.Context, _ string, email string) (*repository.User, *repository.Identity, error) {
	// NOTE: tenantID param from interface is IGNORED — we use r.tenantID.
	const query = `
		SELECT u.id, u.email, u.email_verified,
		       COALESCE(u.name,''), COALESCE(u.given_name,''), COALESCE(u.family_name,''),
		       COALESCE(u.picture,''), COALESCE(u.locale,''), COALESCE(u.language,''),
		       u.source_client_id, u.created_at, u.metadata, u.custom_data,
		       u.disabled_at, u.disabled_until, u.disabled_reason,
		       i.id, i.provider, i.provider_user_id, i.email, i.email_verified, i.password_hash, i.created_at
		FROM app_user u
		LEFT JOIN identity i ON i.user_id = u.id
		    AND i.tenant_id = ?
		    AND i.provider = 'password'
		WHERE u.tenant_id = ? AND u.email = ?
		LIMIT 1
	`

	var user repository.User
	var metadata []byte
	var customData []byte

	// Nullable identity fields (NULL when user has no password identity — social-only users)
	var identityID *string
	var identityProvider *string
	var identityProviderUserID *string
	var identityEmail *string
	var identityEmailVerified *bool
	var pwdHash *string
	var identityCreatedAt *time.Time

	user.TenantID = r.tenantID.String()

	err := r.db.QueryRowContext(ctx, query, r.tenantID.String(), r.tenantID.String(), email).Scan(
		&user.ID, &user.Email, &user.EmailVerified,
		&user.Name, &user.GivenName, &user.FamilyName, &user.Picture, &user.Locale, &user.Language,
		&user.SourceClientID, &user.CreatedAt, &metadata, &customData,
		&user.DisabledAt, &user.DisabledUntil, &user.DisabledReason,
		&identityID, &identityProvider, &identityProviderUserID,
		&identityEmail, &identityEmailVerified, &pwdHash, &identityCreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("mysql_shared: get user by email: %w", err)
	}

	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &user.Metadata); err != nil {
			log.Printf("WARN: mysql_shared: json.Unmarshal metadata for user %s: %v", user.Email, err)
		}
	}
	user.CustomFields = sharedUnmarshalCustomData(customData)

	// Social-only users have no password identity row — return nil identity
	if identityID == nil {
		return &user, nil, nil
	}

	identity := repository.Identity{
		UserID:       user.ID,
		PasswordHash: pwdHash,
	}
	identity.ID = *identityID
	if identityProvider != nil {
		identity.Provider = *identityProvider
	}
	if identityProviderUserID != nil {
		identity.ProviderUserID = *identityProviderUserID
	}
	if identityEmail != nil {
		identity.Email = *identityEmail
	}
	if identityEmailVerified != nil {
		identity.EmailVerified = *identityEmailVerified
	}
	if identityCreatedAt != nil {
		identity.CreatedAt = *identityCreatedAt
	}
	return &user, &identity, nil
}

func (r *sharedUserRepo) GetByID(ctx context.Context, userID string) (*repository.User, error) {
	const query = `
		SELECT id, email, email_verified,
		       COALESCE(name,''), COALESCE(given_name,''), COALESCE(family_name,''),
		       COALESCE(picture,''), COALESCE(locale,''), COALESCE(language,''),
		       source_client_id, created_at, metadata, custom_data,
		       disabled_at, disabled_until, disabled_reason
		FROM app_user
		WHERE tenant_id = ? AND id = ?
	`
	var user repository.User
	var metadata []byte
	var customData []byte
	user.TenantID = r.tenantID.String()
	err := r.db.QueryRowContext(ctx, query, r.tenantID.String(), userID).Scan(
		&user.ID, &user.Email, &user.EmailVerified,
		&user.Name, &user.GivenName, &user.FamilyName, &user.Picture, &user.Locale, &user.Language,
		&user.SourceClientID, &user.CreatedAt, &metadata, &customData,
		&user.DisabledAt, &user.DisabledUntil, &user.DisabledReason,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: get user by id: %w", err)
	}
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &user.Metadata); err != nil {
			log.Printf("WARN: mysql_shared: json.Unmarshal metadata for user %s: %v", user.ID, err)
		}
	}
	user.CustomFields = sharedUnmarshalCustomData(customData)
	return &user, nil
}

func (r *sharedUserRepo) Create(ctx context.Context, input repository.CreateUserInput) (*repository.User, *repository.Identity, error) {
	var user repository.User
	var identity repository.Identity

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	user = repository.User{
		TenantID:     r.tenantID.String(),
		Email:        input.Email,
		Name:         input.Name,
		GivenName:    input.GivenName,
		FamilyName:   input.FamilyName,
		Picture:      input.Picture,
		Locale:       input.Locale,
		CustomFields: input.CustomFields,
		CreatedAt:    time.Now(),
	}
	if input.SourceClientID != "" {
		user.SourceClientID = &input.SourceClientID
	}

	// Ensure custom_data is never nil for JSON serialization
	customData := input.CustomFields
	if customData == nil {
		customData = make(map[string]any)
	}
	customDataJSON, err := json.Marshal(customData)
	if err != nil {
		return nil, nil, fmt.Errorf("mysql_shared: marshal custom_data: %w", err)
	}

	// Generate UUID for user
	userID := uuid.NewString()

	const insertUser = `
		INSERT INTO app_user (id, tenant_id, email, email_verified, name, given_name, family_name, picture, locale, source_client_id, custom_data, created_at)
		VALUES (?, ?, ?, false, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err = tx.ExecContext(ctx, insertUser,
		userID, r.tenantID.String(), user.Email, nullIfEmpty(user.Name), nullIfEmpty(user.GivenName),
		nullIfEmpty(user.FamilyName), nullIfEmpty(user.Picture), nullIfEmpty(user.Locale),
		user.SourceClientID, customDataJSON, user.CreatedAt,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("mysql_shared: insert user: %w", err)
	}
	user.ID = userID

	identity = repository.Identity{
		UserID:       user.ID,
		Provider:     "password",
		Email:        input.Email,
		PasswordHash: &input.PasswordHash,
		CreatedAt:    time.Now(),
	}
	identityID := uuid.NewString()

	const insertIdentity = `
		INSERT INTO identity (id, tenant_id, user_id, provider, email, email_verified, password_hash, created_at)
		VALUES (?, ?, ?, ?, ?, false, ?, ?)
	`
	_, err = tx.ExecContext(ctx, insertIdentity,
		identityID, r.tenantID.String(), user.ID, identity.Provider, identity.Email, input.PasswordHash, identity.CreatedAt,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("mysql_shared: insert identity: %w", err)
	}
	identity.ID = identityID

	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("mysql_shared: commit create user: %w", err)
	}

	return &user, &identity, nil
}

// CreateBatch inserts multiple users in a single transaction.
// All-or-nothing semantics: if any item fails, the entire batch is rolled back.
func (r *sharedUserRepo) CreateBatch(ctx context.Context, _ string, users []repository.CreateUserInput) (created, failed int, err error) {
	if len(users) == 0 {
		return 0, 0, nil
	}

	tx, bErr := r.db.BeginTx(ctx, nil)
	if bErr != nil {
		return 0, len(users), fmt.Errorf("mysql_shared: begin tx: %w", bErr)
	}
	defer tx.Rollback()

	now := time.Now()

	const insertUserSQL = `
		INSERT INTO app_user (id, tenant_id, email, email_verified, name, given_name, family_name, picture, locale, source_client_id, custom_data, created_at)
		VALUES (?, ?, ?, false, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	const insertIdentitySQL = `
		INSERT INTO identity (id, tenant_id, user_id, provider, email, email_verified, password_hash, created_at)
		VALUES (?, ?, ?, 'password', ?, false, ?, ?)
	`

	for i, u := range users {
		userID := uuid.NewString()
		var srcClientID *string
		if u.SourceClientID != "" {
			srcClientID = &u.SourceClientID
		}
		customData := u.CustomFields
		if customData == nil {
			customData = make(map[string]any)
		}
		customDataJSON, jErr := json.Marshal(customData)
		if jErr != nil {
			return 0, len(users), fmt.Errorf("mysql_shared: marshal custom_data for user[%d]: %w", i, jErr)
		}

		_, execErr := tx.ExecContext(ctx, insertUserSQL,
			userID, r.tenantID.String(), u.Email, nullIfEmpty(u.Name), nullIfEmpty(u.GivenName),
			nullIfEmpty(u.FamilyName), nullIfEmpty(u.Picture), nullIfEmpty(u.Locale),
			srcClientID, customDataJSON, now,
		)
		if execErr != nil {
			return 0, len(users), fmt.Errorf("mysql_shared: create batch user[%d] %q: %w", i, u.Email, execErr)
		}

		identityID := uuid.NewString()
		_, execErr = tx.ExecContext(ctx, insertIdentitySQL,
			identityID, r.tenantID.String(), userID, u.Email, u.PasswordHash, now,
		)
		if execErr != nil {
			return 0, len(users), fmt.Errorf("mysql_shared: create batch identity[%d] %q: %w", i, u.Email, execErr)
		}
	}

	if cErr := tx.Commit(); cErr != nil {
		return 0, len(users), fmt.Errorf("mysql_shared: commit batch: %w", cErr)
	}
	return len(users), 0, nil
}

func (r *sharedUserRepo) Update(ctx context.Context, userID string, input repository.UpdateUserInput) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	setClauses := []string{}
	args := []any{}

	if input.Name != nil {
		setClauses = append(setClauses, "name = ?")
		args = append(args, *input.Name)
	}
	if input.GivenName != nil {
		setClauses = append(setClauses, "given_name = ?")
		args = append(args, *input.GivenName)
	}
	if input.FamilyName != nil {
		setClauses = append(setClauses, "family_name = ?")
		args = append(args, *input.FamilyName)
	}
	if input.Picture != nil {
		setClauses = append(setClauses, "picture = ?")
		args = append(args, *input.Picture)
	}
	if input.Locale != nil {
		setClauses = append(setClauses, "locale = ?")
		args = append(args, *input.Locale)
	}
	if input.SourceClientID != nil {
		setClauses = append(setClauses, "source_client_id = ?")
		if *input.SourceClientID == "" {
			args = append(args, nil)
		} else {
			args = append(args, *input.SourceClientID)
		}
	}

	// Merge custom fields into JSON column (shallow merge via JSON_MERGE_PATCH)
	if len(input.CustomFields) > 0 {
		cfJSON, jErr := json.Marshal(input.CustomFields)
		if jErr != nil {
			return fmt.Errorf("mysql_shared: marshal custom_fields: %w", jErr)
		}
		setClauses = append(setClauses, "custom_data = JSON_MERGE_PATCH(COALESCE(custom_data, '{}'), ?)")
		args = append(args, string(cfJSON))
	}

	// Always touch updated_at so callers can detect stale caches.
	setClauses = append(setClauses, "updated_at = NOW(6)")

	if len(setClauses) <= 1 {
		// Only updated_at — nothing meaningful to update
		return nil
	}

	query := fmt.Sprintf("UPDATE app_user SET %s WHERE tenant_id = ? AND id = ?",
		strings.Join(setClauses, ", "))
	args = append(args, r.tenantID.String(), userID)

	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return repository.ErrNotFound
	}

	return tx.Commit()
}

func (r *sharedUserRepo) Disable(ctx context.Context, userID, by, reason string, until *time.Time) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	const query = `
		UPDATE app_user SET
			disabled_at = NOW(6),
			disabled_until = ?,
			disabled_reason = ?,
			updated_at = NOW(6)
		WHERE tenant_id = ? AND id = ?
	`
	result, err := tx.ExecContext(ctx, query, until, reason, r.tenantID.String(), userID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return repository.ErrNotFound
	}
	return tx.Commit()
}

func (r *sharedUserRepo) Enable(ctx context.Context, userID, by string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	const query = `
		UPDATE app_user SET
			disabled_at = NULL,
			disabled_until = NULL,
			disabled_reason = NULL,
			updated_at = NOW(6)
		WHERE tenant_id = ? AND id = ?
	`
	result, err := tx.ExecContext(ctx, query, r.tenantID.String(), userID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return repository.ErrNotFound
	}
	return tx.Commit()
}

func (r *sharedUserRepo) CheckPassword(hash *string, plain string) bool {
	if hash == nil || strings.TrimSpace(*hash) == "" {
		return false
	}
	return secpassword.Verify(plain, *hash)
}

func (r *sharedUserRepo) SetEmailVerified(ctx context.Context, userID string, verified bool) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	const query = `UPDATE app_user SET email_verified = ?, updated_at = NOW(6) WHERE tenant_id = ? AND id = ?`
	result, err := tx.ExecContext(ctx, query, verified, r.tenantID.String(), userID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return repository.ErrNotFound
	}
	return tx.Commit()
}

func (r *sharedUserRepo) UpdatePasswordHash(ctx context.Context, userID, newHash string) error {
	return r.RotatePasswordHash(ctx, userID, newHash, 0)
}

func (r *sharedUserRepo) ListPasswordHistory(ctx context.Context, userID string, limit int) ([]string, error) {
	if limit <= 0 {
		return []string{}, nil
	}

	history := make([]string, 0, limit)
	var currentHash string
	err := r.db.QueryRowContext(ctx,
		`SELECT password_hash FROM identity WHERE tenant_id = ? AND user_id = ? AND provider = 'password'`,
		r.tenantID.String(), userID,
	).Scan(&currentHash)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	} else if strings.TrimSpace(currentHash) != "" {
		history = append(history, currentHash)
	}

	remaining := limit - len(history)
	if remaining <= 0 {
		return history, nil
	}

	const query = `
		SELECT hash
		FROM password_history
		WHERE tenant_id = ? AND user_id = ?
		ORDER BY created_at DESC
		LIMIT ?
	`
	rows, err := r.db.QueryContext(ctx, query, r.tenantID.String(), userID, remaining)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, err
		}
		if strings.TrimSpace(hash) != "" {
			history = append(history, hash)
		}
	}
	return history, rows.Err()
}

func (r *sharedUserRepo) RotatePasswordHash(ctx context.Context, userID, newHash string, keepHistory int) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	var currentHash string
	err = tx.QueryRowContext(ctx,
		`SELECT password_hash FROM identity WHERE tenant_id = ? AND user_id = ? AND provider = 'password' FOR UPDATE`,
		r.tenantID.String(), userID,
	).Scan(&currentHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return repository.ErrNotFound
		}
		return err
	}

	if keepHistory > 0 && strings.TrimSpace(currentHash) != "" {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO password_history (id, tenant_id, user_id, hash, algorithm, created_at)
			VALUES (?, ?, ?, ?, ?, NOW(6))
		`, uuid.NewString(), r.tenantID.String(), userID, currentHash, "argon2id")
		if err != nil {
			return err
		}
	}

	result, err := tx.ExecContext(ctx,
		`UPDATE identity SET password_hash = ?, updated_at = NOW(6) WHERE tenant_id = ? AND user_id = ? AND provider = 'password'`,
		newHash, r.tenantID.String(), userID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return repository.ErrNotFound
	}

	if keepHistory > 0 {
		// Find stale history entries beyond keepHistory limit
		staleRows, qErr := tx.QueryContext(ctx, `
			SELECT id FROM password_history
			WHERE tenant_id = ? AND user_id = ?
			ORDER BY created_at DESC
			LIMIT 18446744073709551615 OFFSET ?
		`, r.tenantID.String(), userID, keepHistory)
		if qErr != nil {
			return qErr
		}
		defer staleRows.Close()

		var staleIDs []string
		for staleRows.Next() {
			var id string
			if err := staleRows.Scan(&id); err != nil {
				return err
			}
			staleIDs = append(staleIDs, id)
		}
		if err := staleRows.Err(); err != nil {
			return err
		}
		if len(staleIDs) > 0 {
			placeholders := make([]string, len(staleIDs))
			delArgs := []any{r.tenantID.String()}
			for i, id := range staleIDs {
				placeholders[i] = "?"
				delArgs = append(delArgs, id)
			}
			_, err = tx.ExecContext(ctx,
				fmt.Sprintf(`DELETE FROM password_history WHERE tenant_id = ? AND id IN (%s)`, strings.Join(placeholders, ",")),
				delArgs...,
			)
			if err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}

func (r *sharedUserRepo) List(ctx context.Context, _ string, filter repository.ListUsersFilter) ([]repository.User, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	var query string
	var args []any

	if filter.Search != "" {
		query = `SELECT id, email, email_verified, COALESCE(name,''), COALESCE(given_name,''), COALESCE(family_name,''),
		         COALESCE(picture,''), COALESCE(locale,''), COALESCE(language,''),
		         source_client_id, created_at, metadata, custom_data, disabled_at, disabled_until, disabled_reason
		         FROM app_user WHERE tenant_id = ? AND (email LIKE ? OR name LIKE ?)
		         ORDER BY created_at DESC LIMIT ? OFFSET ?`
		searchTerm := "%" + filter.Search + "%"
		args = []any{r.tenantID.String(), searchTerm, searchTerm, limit, offset}
	} else {
		query = `SELECT id, email, email_verified, COALESCE(name,''), COALESCE(given_name,''), COALESCE(family_name,''),
		         COALESCE(picture,''), COALESCE(locale,''), COALESCE(language,''),
		         source_client_id, created_at, metadata, custom_data, disabled_at, disabled_until, disabled_reason
		         FROM app_user WHERE tenant_id = ?
		         ORDER BY created_at DESC LIMIT ? OFFSET ?`
		args = []any{r.tenantID.String(), limit, offset}
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("mysql_shared: list users: %w", err)
	}
	defer rows.Close()

	var users []repository.User
	for rows.Next() {
		var u repository.User
		u.TenantID = r.tenantID.String()
		var metadata []byte
		var customData []byte
		if err := rows.Scan(
			&u.ID, &u.Email, &u.EmailVerified,
			&u.Name, &u.GivenName, &u.FamilyName, &u.Picture, &u.Locale, &u.Language,
			&u.SourceClientID, &u.CreatedAt, &metadata, &customData,
			&u.DisabledAt, &u.DisabledUntil, &u.DisabledReason,
		); err != nil {
			return nil, fmt.Errorf("mysql_shared: scan user: %w", err)
		}
		if len(metadata) > 0 {
			if err := json.Unmarshal(metadata, &u.Metadata); err != nil {
				log.Printf("WARN: mysql_shared: json.Unmarshal metadata for user %s: %v", u.ID, err)
			}
		}
		u.CustomFields = sharedUnmarshalCustomData(customData)
		users = append(users, u)
	}
	return users, rows.Err()
}

func (r *sharedUserRepo) Delete(ctx context.Context, userID string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql_shared: begin tx: %w", err)
	}
	defer tx.Rollback()

	// Delete dependencies in FK-safe order
	depTables := []string{
		"password_history", "webauthn_credential",
		"sessions", "user_consent", "mfa_recovery_code", "mfa_trusted_device", "mfa_totp",
		"password_reset_token", "email_verification_token",
		"rbac_user_role", "refresh_token", "identity",
	}
	for _, table := range depTables {
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf("DELETE FROM %s WHERE tenant_id = ? AND user_id = ?", table),
			r.tenantID.String(), userID,
		); err != nil {
			return fmt.Errorf("delete from %s: %w", table, err)
		}
	}
	result, err := tx.ExecContext(ctx, "DELETE FROM app_user WHERE tenant_id = ? AND id = ?", r.tenantID.String(), userID)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return repository.ErrNotFound
	}
	return tx.Commit()
}
