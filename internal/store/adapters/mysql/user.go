// Package mysql implementa UserRepository para MySQL.
package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	secpassword "github.com/dropDatabas3/hellojohn/internal/security/password"
)

// Verificar que implementa la interfaz
var _ repository.UserRepository = (*userRepo)(nil)

// GetByEmail busca un usuario por email con su identidad password.
func (r *userRepo) GetByEmail(ctx context.Context, tenantID, email string) (*repository.User, *repository.Identity, error) {
	const query = `
		SELECT u.id, u.email, u.email_verified, COALESCE(u.name, ''),
		       COALESCE(u.given_name, ''), COALESCE(u.family_name, ''),
		       COALESCE(u.picture, ''), COALESCE(u.locale, ''),
		       COALESCE(u.language, ''), u.source_client_id, u.created_at, u.metadata, u.custom_data,
		       u.disabled_at, u.disabled_until, u.disabled_reason,
		       i.id, i.provider, i.provider_user_id, i.email,
		       i.email_verified, i.password_hash, i.created_at
		FROM app_user u
		LEFT JOIN identity i ON i.user_id = u.id AND i.provider = 'password'
		WHERE u.email = ?
		LIMIT 1
	`

	var user repository.User
	var identity repository.Identity
	var pwdHash sql.NullString
	var metadata []byte
	var customData []byte
	var sourceClientID sql.NullString
	var disabledAt, disabledUntil sql.NullTime
	var disabledReason sql.NullString

	// Identity fields (may be NULL if no password identity)
	var identityID, identityProvider, identityProviderUID sql.NullString
	var identityEmail sql.NullString
	var identityEmailVerified sql.NullBool
	var identityCreatedAt sql.NullTime

	user.TenantID = tenantID

	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.EmailVerified,
		&user.Name, &user.GivenName, &user.FamilyName,
		&user.Picture, &user.Locale, &user.Language,
		&sourceClientID, &user.CreatedAt, &metadata, &customData,
		&disabledAt, &disabledUntil, &disabledReason,
		&identityID, &identityProvider, &identityProviderUID,
		&identityEmail, &identityEmailVerified, &pwdHash, &identityCreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("mysql: get user by email: %w", err)
	}

	// Map nullable fields
	user.SourceClientID = nullStringToPtr(sourceClientID)
	user.DisabledAt = nullTimeToPtr(disabledAt)
	user.DisabledUntil = nullTimeToPtr(disabledUntil)
	user.DisabledReason = nullStringToPtr(disabledReason)
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &user.Metadata); err != nil {
			log.Printf("WARN: mysql: json.Unmarshal metadata for user %s: %v", user.Email, err)
		}
	}
	user.CustomFields = mysqlUnmarshalCustomData(customData)

	// Build identity if exists
	if identityID.Valid {
		identity.ID = identityID.String
		identity.UserID = user.ID
		identity.Provider = identityProvider.String
		if identityProviderUID.Valid {
			identity.ProviderUserID = identityProviderUID.String
		}
		identity.Email = identityEmail.String
		identity.EmailVerified = identityEmailVerified.Valid && identityEmailVerified.Bool
		identity.PasswordHash = nullStringToPtr(pwdHash)
		if identityCreatedAt.Valid {
			identity.CreatedAt = identityCreatedAt.Time
		}
	}

	// Social-only users have no password identity row — return nil identity
	if !identityID.Valid {
		return &user, nil, nil
	}

	return &user, &identity, nil
}

// GetByID obtiene un usuario por su ID.
func (r *userRepo) GetByID(ctx context.Context, userID string) (*repository.User, error) {
	const query = `
		SELECT id, email, email_verified, COALESCE(name, ''),
		       COALESCE(given_name, ''), COALESCE(family_name, ''),
		       COALESCE(picture, ''), COALESCE(locale, ''),
		       COALESCE(language, ''), source_client_id, created_at, metadata, custom_data,
		       disabled_at, disabled_until, disabled_reason
		FROM app_user WHERE id = ?
	`

	var user repository.User
	var metadata []byte
	var customData []byte
	var sourceClientID sql.NullString
	var disabledAt, disabledUntil sql.NullTime
	var disabledReason sql.NullString

	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&user.ID, &user.Email, &user.EmailVerified,
		&user.Name, &user.GivenName, &user.FamilyName,
		&user.Picture, &user.Locale, &user.Language,
		&sourceClientID, &user.CreatedAt, &metadata, &customData,
		&disabledAt, &disabledUntil, &disabledReason,
	)
	if err == sql.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("mysql: get user by id: %w", err)
	}

	user.SourceClientID = nullStringToPtr(sourceClientID)
	user.DisabledAt = nullTimeToPtr(disabledAt)
	user.DisabledUntil = nullTimeToPtr(disabledUntil)
	user.DisabledReason = nullStringToPtr(disabledReason)
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &user.Metadata); err != nil {
			log.Printf("WARN: mysql: json.Unmarshal metadata for user %s: %v", user.ID, err)
		}
	}
	user.CustomFields = mysqlUnmarshalCustomData(customData)

	return &user, nil
}

// mysqlUnmarshalCustomData deserializes the custom_data JSON column into a map.
// Returns an empty (non-nil) map on NULL or invalid JSON.
func mysqlUnmarshalCustomData(data []byte) map[string]any {
	result := make(map[string]any)
	if len(data) == 0 {
		return result
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return make(map[string]any)
	}
	return result
}

// List lista usuarios con filtros y paginación.
func (r *userRepo) List(ctx context.Context, tenantID string, filter repository.ListUsersFilter) ([]repository.User, error) {
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

	const selectCols = `id, email, email_verified, COALESCE(name,''), COALESCE(given_name,''), COALESCE(family_name,''),
		COALESCE(picture,''), COALESCE(locale,''), COALESCE(language,''),
		source_client_id, created_at, metadata, custom_data,
		disabled_at, disabled_until, disabled_reason`

	var query string
	var args []any

	if filter.Search != "" {
		query = `SELECT ` + selectCols + ` FROM app_user WHERE (email LIKE ? OR name LIKE ?) ORDER BY created_at DESC LIMIT ? OFFSET ?`
		searchPattern := "%" + filter.Search + "%"
		args = []any{searchPattern, searchPattern, limit, offset}
	} else {
		query = `SELECT ` + selectCols + ` FROM app_user ORDER BY created_at DESC LIMIT ? OFFSET ?`
		args = []any{limit, offset}
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("mysql: list users: %w", err)
	}
	defer rows.Close()

	var users []repository.User
	for rows.Next() {
		var u repository.User
		u.TenantID = tenantID
		var metadata []byte
		var customData []byte
		var sourceClientID sql.NullString
		var disabledAt, disabledUntil sql.NullTime
		var disabledReason sql.NullString

		if err := rows.Scan(
			&u.ID, &u.Email, &u.EmailVerified,
			&u.Name, &u.GivenName, &u.FamilyName,
			&u.Picture, &u.Locale, &u.Language,
			&sourceClientID, &u.CreatedAt, &metadata, &customData,
			&disabledAt, &disabledUntil, &disabledReason,
		); err != nil {
			return nil, fmt.Errorf("mysql: scan user: %w", err)
		}

		u.SourceClientID = nullStringToPtr(sourceClientID)
		u.DisabledAt = nullTimeToPtr(disabledAt)
		u.DisabledUntil = nullTimeToPtr(disabledUntil)
		u.DisabledReason = nullStringToPtr(disabledReason)
		if len(metadata) > 0 {
			if err := json.Unmarshal(metadata, &u.Metadata); err != nil {
				log.Printf("WARN: mysql: json.Unmarshal metadata for user %s: %v", u.ID, err)
			}
		}
		u.CustomFields = mysqlUnmarshalCustomData(customData)
		users = append(users, u)
	}

	return users, rows.Err()
}

// Create crea un nuevo usuario con su identidad password.
func (r *userRepo) Create(ctx context.Context, input repository.CreateUserInput) (*repository.User, *repository.Identity, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("mysql: begin tx: %w", err)
	}
	defer tx.Rollback()

	userID := uuid.New().String()
	now := time.Now()

	user := &repository.User{
		ID:           userID,
		TenantID:     input.TenantID,
		Email:        input.Email,
		Name:         input.Name,
		GivenName:    input.GivenName,
		FamilyName:   input.FamilyName,
		Picture:      input.Picture,
		Locale:       input.Locale,
		CustomFields: input.CustomFields,
		CreatedAt:    now,
	}
	if input.SourceClientID != "" {
		user.SourceClientID = &input.SourceClientID
	}

	// Serialize custom fields to JSON — database/sql does NOT auto-serialize maps
	customData := input.CustomFields
	if customData == nil {
		customData = make(map[string]any)
	}
	customDataJSON, err := json.Marshal(customData)
	if err != nil {
		return nil, nil, fmt.Errorf("mysql: marshal custom_data: %w", err)
	}

	const insertUser = `
		INSERT INTO app_user (id, email, email_verified, name, given_name, family_name, picture, locale, source_client_id, custom_data, created_at)
		VALUES (?, ?, false, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err = tx.ExecContext(ctx, insertUser,
		userID, user.Email,
		nullIfEmpty(input.Name), nullIfEmpty(input.GivenName),
		nullIfEmpty(input.FamilyName), nullIfEmpty(input.Picture),
		nullIfEmpty(input.Locale), user.SourceClientID,
		customDataJSON, now,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("mysql: insert user: %w", err)
	}

	identityID := uuid.New().String()
	identity := &repository.Identity{
		ID:           identityID,
		UserID:       userID,
		Provider:     "password",
		Email:        input.Email,
		PasswordHash: &input.PasswordHash,
		CreatedAt:    now,
	}

	const insertIdentity = `
		INSERT INTO identity (id, user_id, provider, email, email_verified, password_hash, created_at)
		VALUES (?, ?, ?, ?, false, ?, ?)
	`
	_, err = tx.ExecContext(ctx, insertIdentity,
		identityID, userID, "password", input.Email, input.PasswordHash, now,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("mysql: insert identity: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("mysql: commit tx: %w", err)
	}

	return user, identity, nil
}

func (r *userRepo) CreateBatch(ctx context.Context, tenantID string, users []repository.CreateUserInput) (created, failed int, err error) {
	for _, u := range users {
		if strings.TrimSpace(u.TenantID) == "" {
			u.TenantID = tenantID
		}
		if _, _, createErr := r.Create(ctx, u); createErr != nil {
			failed++
			continue
		}
		created++
	}
	return created, failed, nil
}

// Update actualiza un usuario existente.
func (r *userRepo) Update(ctx context.Context, userID string, input repository.UpdateUserInput) error {
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

	// Merge custom fields into JSON column via JSON_MERGE_PATCH
	if len(input.CustomFields) > 0 {
		customDataJSON, err := json.Marshal(input.CustomFields)
		if err != nil {
			return fmt.Errorf("mysql: marshal custom_data for update: %w", err)
		}
		setClauses = append(setClauses, "custom_data = JSON_MERGE_PATCH(COALESCE(custom_data, '{}'), ?)")
		args = append(args, customDataJSON)
	}

	if len(setClauses) == 0 {
		return nil
	}

	// Always touch updated_at
	setClauses = append(setClauses, "updated_at = NOW()")

	args = append(args, userID)
	query := fmt.Sprintf("UPDATE app_user SET %s WHERE id = ?", strings.Join(setClauses, ", "))

	_, err := r.db.ExecContext(ctx, query, args...)
	return err
}

// Delete elimina un usuario y sus dependencias.
func (r *userRepo) Delete(ctx context.Context, userID string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("mysql: begin tx: %w", err)
	}
	defer tx.Rollback()

	// Delete dependencies (tables may not exist in some configurations)
	tables := []string{"identity", "refresh_token", "user_consent", "user_mfa_totp", "mfa_recovery_code", "trusted_device", "rbac_user_role", "sessions"}
	for _, table := range tables {
		query := fmt.Sprintf("DELETE FROM %s WHERE user_id = ?", table)
		_, _ = tx.ExecContext(ctx, query, userID) // Ignore errors (table may not exist)
	}

	// Delete user (must exist)
	result, err := tx.ExecContext(ctx, `DELETE FROM app_user WHERE id = ?`, userID)
	if err != nil {
		return fmt.Errorf("mysql: delete user: %w", err)
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return repository.ErrNotFound
	}

	return tx.Commit()
}

// Disable deshabilita un usuario.
func (r *userRepo) Disable(ctx context.Context, userID, by, reason string, until *time.Time) error {
	const query = `
		UPDATE app_user SET
			disabled_at = NOW(),
			disabled_until = ?,
			disabled_reason = ?
		WHERE id = ?
	`
	_, err := r.db.ExecContext(ctx, query, until, reason, userID)
	return err
}

// Enable habilita un usuario deshabilitado.
func (r *userRepo) Enable(ctx context.Context, userID, by string) error {
	const query = `
		UPDATE app_user SET
			disabled_at = NULL,
			disabled_until = NULL,
			disabled_reason = NULL
		WHERE id = ?
	`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

// CheckPassword verifica si el password coincide con el hash.
func (r *userRepo) CheckPassword(hash *string, plain string) bool {
	if hash == nil || strings.TrimSpace(*hash) == "" {
		return false
	}
	return secpassword.Verify(plain, *hash)
}

// SetEmailVerified marca el email como verificado.
func (r *userRepo) SetEmailVerified(ctx context.Context, userID string, verified bool) error {
	const query = `UPDATE app_user SET email_verified = ? WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, verified, userID)
	return err
}

// UpdatePasswordHash actualiza el hash de password en la identity.
func (r *userRepo) UpdatePasswordHash(ctx context.Context, userID, newHash string) error {
	return r.RotatePasswordHash(ctx, userID, newHash, 0)
}

// ListPasswordHistory retorna hashes históricos de password (más nuevos primero).
func (r *userRepo) ListPasswordHistory(ctx context.Context, userID string, limit int) ([]string, error) {
	if limit <= 0 {
		return []string{}, nil
	}

	history := make([]string, 0, limit)
	var currentHash sql.NullString
	if err := r.db.QueryRowContext(ctx,
		`SELECT password_hash FROM identity WHERE user_id = ? AND provider = 'password'`,
		userID,
	).Scan(&currentHash); err != nil {
		if err != sql.ErrNoRows {
			return nil, err
		}
	} else if currentHash.Valid && strings.TrimSpace(currentHash.String) != "" {
		history = append(history, currentHash.String)
	}

	remaining := limit - len(history)
	if remaining <= 0 {
		return history, nil
	}

	const query = `
		SELECT hash
		FROM password_history
		WHERE user_id = ?
		ORDER BY created_at DESC
		LIMIT ?
	`
	rows, err := r.db.QueryContext(ctx, query, userID, remaining)
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
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return history, nil
}

// RotatePasswordHash rota el hash actual en transacción e inserta el hash previo en history.
func (r *userRepo) RotatePasswordHash(ctx context.Context, userID, newHash string, keepHistory int) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var currentHash sql.NullString
	err = tx.QueryRowContext(ctx,
		`SELECT password_hash FROM identity WHERE user_id = ? AND provider = 'password' FOR UPDATE`,
		userID,
	).Scan(&currentHash)
	if err == sql.ErrNoRows {
		return repository.ErrNotFound
	}
	if err != nil {
		return err
	}

	if keepHistory > 0 && currentHash.Valid && strings.TrimSpace(currentHash.String) != "" {
		const insertHistory = `
			INSERT INTO password_history (id, user_id, hash, algorithm, created_at)
			VALUES (?, ?, ?, ?, ?)
		`
		if _, err := tx.ExecContext(ctx, insertHistory, uuid.New().String(), userID, currentHash.String, "argon2id", time.Now().UTC()); err != nil {
			return err
		}
	}

	result, err := tx.ExecContext(ctx,
		`UPDATE identity SET password_hash = ?, updated_at = NOW() WHERE user_id = ? AND provider = 'password'`,
		newHash, userID,
	)
	if err != nil {
		return err
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return repository.ErrNotFound
	}

	if keepHistory > 0 {
		rows, err := tx.QueryContext(ctx, `
			SELECT id
			FROM password_history
			WHERE user_id = ?
			ORDER BY created_at DESC
			LIMIT 18446744073709551615 OFFSET ?
		`, userID, keepHistory)
		if err != nil {
			return err
		}

		var staleIDs []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			staleIDs = append(staleIDs, id)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()

		for _, staleID := range staleIDs {
			if _, err := tx.ExecContext(ctx, `DELETE FROM password_history WHERE user_id = ? AND id = ?`, userID, staleID); err != nil {
				return err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}
