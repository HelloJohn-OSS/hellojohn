package pg_shared

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	secpassword "github.com/dropDatabas3/hellojohn/internal/security/password"
)

// ─── sharedUserRepo ───────────────────────────────────────────────

// sharedUserRepo implements repository.UserRepository for Global Data Plane.
// ALL queries include WHERE tenant_id = $X as first line of defense.
// Writes also use execWithRLS() as second line (DB-level RLS).
type sharedUserRepo struct {
	pool     *pgxpool.Pool
	tenantID uuid.UUID
}

// sharedUnmarshalCustomData deserializes the custom_data JSONB column into a map.
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
		    AND i.tenant_id = $1
		    AND i.provider = 'password'
		WHERE u.tenant_id = $1 AND u.email = $2
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

	err := r.pool.QueryRow(ctx, query, r.tenantID, email).Scan(
		&user.ID, &user.Email, &user.EmailVerified,
		&user.Name, &user.GivenName, &user.FamilyName, &user.Picture, &user.Locale, &user.Language,
		&user.SourceClientID, &user.CreatedAt, &metadata, &customData,
		&user.DisabledAt, &user.DisabledUntil, &user.DisabledReason,
		&identityID, &identityProvider, &identityProviderUserID,
		&identityEmail, &identityEmailVerified, &pwdHash, &identityCreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("pg_shared: get user by email: %w", err)
	}

	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &user.Metadata); err != nil {
			log.Printf("WARN: pg_shared: json.Unmarshal metadata for user %s: %v", user.Email, err)
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
		WHERE tenant_id = $1 AND id = $2
	`
	var user repository.User
	var metadata []byte
	var customData []byte
	user.TenantID = r.tenantID.String()
	err := r.pool.QueryRow(ctx, query, r.tenantID, userID).Scan(
		&user.ID, &user.Email, &user.EmailVerified,
		&user.Name, &user.GivenName, &user.FamilyName, &user.Picture, &user.Locale, &user.Language,
		&user.SourceClientID, &user.CreatedAt, &metadata, &customData,
		&user.DisabledAt, &user.DisabledUntil, &user.DisabledReason,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("pg_shared: get user by id: %w", err)
	}
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &user.Metadata); err != nil {
			log.Printf("WARN: pg_shared: json.Unmarshal metadata for user %s: %v", user.ID, err)
		}
	}
	user.CustomFields = sharedUnmarshalCustomData(customData)
	return &user, nil
}

func (r *sharedUserRepo) Create(ctx context.Context, input repository.CreateUserInput) (*repository.User, *repository.Identity, error) {
	var user repository.User
	var identity repository.Identity

	err := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
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

		// Ensure custom_data is never nil for JSONB serialization
		customData := input.CustomFields
		if customData == nil {
			customData = make(map[string]any)
		}

		const insertUser = `
			INSERT INTO app_user (tenant_id, email, email_verified, name, given_name, family_name, picture, locale, source_client_id, custom_data, created_at)
			VALUES ($1, $2, false, $3, $4, $5, $6, $7, $8, $9, $10)
			RETURNING id
		`
		err := tx.QueryRow(ctx, insertUser,
			r.tenantID, user.Email, nullIfEmpty(user.Name), nullIfEmpty(user.GivenName),
			nullIfEmpty(user.FamilyName), nullIfEmpty(user.Picture), nullIfEmpty(user.Locale),
			user.SourceClientID, customData, user.CreatedAt,
		).Scan(&user.ID)
		if err != nil {
			return fmt.Errorf("insert user: %w", err)
		}

		identity = repository.Identity{
			UserID:       user.ID,
			Provider:     "password",
			Email:        input.Email,
			PasswordHash: &input.PasswordHash,
			CreatedAt:    time.Now(),
		}
		const insertIdentity = `
			INSERT INTO identity (tenant_id, user_id, provider, email, email_verified, password_hash, created_at)
			VALUES ($1, $2, $3, $4, false, $5, $6)
			RETURNING id
		`
		return tx.QueryRow(ctx, insertIdentity,
			r.tenantID, user.ID, identity.Provider, identity.Email, input.PasswordHash, identity.CreatedAt,
		).Scan(&identity.ID)
	})

	if err != nil {
		return nil, nil, fmt.Errorf("pg_shared: create user: %w", err)
	}
	return &user, &identity, nil
}

// CreateBatch inserts multiple users in a single transaction using pgx.Batch
// for efficiency (2 round-trips instead of 2N). All-or-nothing semantics:
// if any item fails, the entire batch is rolled back (GDP-002 fix).
func (r *sharedUserRepo) CreateBatch(ctx context.Context, _ string, users []repository.CreateUserInput) (created, failed int, err error) {
	if len(users) == 0 {
		return 0, 0, nil
	}

	batchErr := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		now := time.Now()

		// Phase 1: batch-insert all app_user rows, collect RETURNING ids.
		const insertUserSQL = `
			INSERT INTO app_user (tenant_id, email, email_verified, name, given_name, family_name, picture, locale, source_client_id, custom_data, created_at)
			VALUES ($1, $2, false, $3, $4, $5, $6, $7, $8, $9, $10)
			RETURNING id
		`
		userBatch := &pgx.Batch{}
		for _, u := range users {
			var srcClientID *string
			if u.SourceClientID != "" {
				srcClientID = &u.SourceClientID
			}
			customData := u.CustomFields
			if customData == nil {
				customData = make(map[string]any)
			}
			userBatch.Queue(insertUserSQL,
				r.tenantID, u.Email, nullIfEmpty(u.Name), nullIfEmpty(u.GivenName),
				nullIfEmpty(u.FamilyName), nullIfEmpty(u.Picture), nullIfEmpty(u.Locale),
				srcClientID, customData, now,
			)
		}
		br := tx.SendBatch(ctx, userBatch)
		userIDs := make([]string, len(users))
		for i := range users {
			if err := br.QueryRow().Scan(&userIDs[i]); err != nil {
				br.Close()
				return fmt.Errorf("pg_shared: create batch user[%d] %q: %w", i, users[i].Email, err)
			}
		}
		br.Close()

		// Phase 2: batch-insert all identity rows with the collected user IDs.
		const insertIdentitySQL = `
			INSERT INTO identity (tenant_id, user_id, provider, email, email_verified, password_hash, created_at)
			VALUES ($1, $2, 'password', $3, false, $4, $5)
		`
		identityBatch := &pgx.Batch{}
		for i, u := range users {
			identityBatch.Queue(insertIdentitySQL, r.tenantID, userIDs[i], u.Email, u.PasswordHash, now)
		}
		ir := tx.SendBatch(ctx, identityBatch)
		defer ir.Close()
		for i := range users {
			if _, execErr := ir.Exec(); execErr != nil {
				return fmt.Errorf("pg_shared: create batch identity[%d] %q: %w", i, users[i].Email, execErr)
			}
		}
		return nil
	})

	if batchErr != nil {
		return 0, len(users), batchErr
	}
	return len(users), 0, nil
}

func (r *sharedUserRepo) Update(ctx context.Context, userID string, input repository.UpdateUserInput) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		setClauses := []string{}
		args := []any{r.tenantID, userID}
		argIdx := 3

		if input.Name != nil {
			setClauses = append(setClauses, fmt.Sprintf("name = $%d", argIdx))
			args = append(args, *input.Name)
			argIdx++
		}
		if input.GivenName != nil {
			setClauses = append(setClauses, fmt.Sprintf("given_name = $%d", argIdx))
			args = append(args, *input.GivenName)
			argIdx++
		}
		if input.FamilyName != nil {
			setClauses = append(setClauses, fmt.Sprintf("family_name = $%d", argIdx))
			args = append(args, *input.FamilyName)
			argIdx++
		}
		if input.Picture != nil {
			setClauses = append(setClauses, fmt.Sprintf("picture = $%d", argIdx))
			args = append(args, *input.Picture)
			argIdx++
		}
		if input.Locale != nil {
			setClauses = append(setClauses, fmt.Sprintf("locale = $%d", argIdx))
			args = append(args, *input.Locale)
			argIdx++
		}
		if input.SourceClientID != nil {
			setClauses = append(setClauses, fmt.Sprintf("source_client_id = $%d", argIdx))
			if *input.SourceClientID == "" {
				args = append(args, nil)
			} else {
				args = append(args, *input.SourceClientID)
			}
			argIdx++
		}

		// Merge custom fields into JSONB column (shallow merge via ||)
		if len(input.CustomFields) > 0 {
			setClauses = append(setClauses, fmt.Sprintf("custom_data = COALESCE(custom_data, '{}'::jsonb) || $%d::jsonb", argIdx))
			args = append(args, input.CustomFields)
			argIdx++
		}

		// Always touch updated_at so callers can detect stale caches.
		setClauses = append(setClauses, "updated_at = NOW()")

		if len(setClauses) <= 1 {
			// Only updated_at — nothing meaningful to update
			return nil
		}

		query := fmt.Sprintf("UPDATE app_user SET %s WHERE tenant_id = $1 AND id = $2",
			strings.Join(setClauses, ", "))
		tag, err := tx.Exec(ctx, query, args...)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *sharedUserRepo) Disable(ctx context.Context, userID, by, reason string, until *time.Time) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		const query = `
			UPDATE app_user SET
				disabled_at = NOW(),
				disabled_until = $3,
				disabled_reason = $4,
				updated_at = NOW()
			WHERE tenant_id = $1 AND id = $2
		`
		tag, err := tx.Exec(ctx, query, r.tenantID, userID, until, reason)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *sharedUserRepo) Enable(ctx context.Context, userID, by string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		const query = `
			UPDATE app_user SET
				disabled_at = NULL,
				disabled_until = NULL,
				disabled_reason = NULL,
				updated_at = NOW()
			WHERE tenant_id = $1 AND id = $2
		`
		tag, err := tx.Exec(ctx, query, r.tenantID, userID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *sharedUserRepo) CheckPassword(hash *string, plain string) bool {
	if hash == nil || strings.TrimSpace(*hash) == "" {
		return false
	}
	return secpassword.Verify(plain, *hash)
}

func (r *sharedUserRepo) SetEmailVerified(ctx context.Context, userID string, verified bool) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		const query = `UPDATE app_user SET email_verified = $3, updated_at = NOW() WHERE tenant_id = $1 AND id = $2`
		tag, err := tx.Exec(ctx, query, r.tenantID, userID, verified)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
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
	if err := r.pool.QueryRow(ctx,
		`SELECT password_hash FROM identity WHERE tenant_id = $1 AND user_id = $2 AND provider = 'password'`,
		r.tenantID, userID,
	).Scan(&currentHash); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
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
		WHERE tenant_id = $1 AND user_id = $2
		ORDER BY created_at DESC
		LIMIT $3
	`
	rows, err := r.pool.Query(ctx, query, r.tenantID, userID, remaining)
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
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		var currentHash string
		err := tx.QueryRow(ctx,
			`SELECT password_hash FROM identity WHERE tenant_id = $1 AND user_id = $2 AND provider = 'password' FOR UPDATE`,
			r.tenantID, userID,
		).Scan(&currentHash)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			return err
		}

		if keepHistory > 0 && strings.TrimSpace(currentHash) != "" {
			_, err = tx.Exec(ctx, `
				INSERT INTO password_history (id, tenant_id, user_id, hash, algorithm, created_at)
				VALUES ($1, $2, $3, $4, $5, NOW())
			`, uuid.NewString(), r.tenantID, userID, currentHash, "argon2id")
			if err != nil {
				return err
			}
		}

		tag, err := tx.Exec(ctx,
			`UPDATE identity SET password_hash = $3, updated_at = NOW() WHERE tenant_id = $1 AND user_id = $2 AND provider = 'password'`,
			r.tenantID, userID, newHash)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}

		if keepHistory > 0 {
			rows, err := tx.Query(ctx, `
				SELECT id FROM password_history
				WHERE tenant_id = $1 AND user_id = $2
				ORDER BY created_at DESC
				OFFSET $3
			`, r.tenantID, userID, keepHistory)
			if err != nil {
				return err
			}
			defer rows.Close()

			var staleIDs []string
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					return err
				}
				staleIDs = append(staleIDs, id)
			}
			if err := rows.Err(); err != nil {
				return err
			}
			if len(staleIDs) > 0 {
				_, err = tx.Exec(ctx,
					`DELETE FROM password_history WHERE tenant_id = $1 AND id = ANY($2)`,
					r.tenantID, staleIDs,
				)
				if err != nil {
					return err
				}
			}
		}

		return nil
	})
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
		         FROM app_user WHERE tenant_id = $1 AND (email ILIKE $2 OR name ILIKE $2)
		         ORDER BY created_at DESC LIMIT $3 OFFSET $4`
		args = []any{r.tenantID, "%" + filter.Search + "%", limit, offset}
	} else {
		query = `SELECT id, email, email_verified, COALESCE(name,''), COALESCE(given_name,''), COALESCE(family_name,''),
		         COALESCE(picture,''), COALESCE(locale,''), COALESCE(language,''),
		         source_client_id, created_at, metadata, custom_data, disabled_at, disabled_until, disabled_reason
		         FROM app_user WHERE tenant_id = $1
		         ORDER BY created_at DESC LIMIT $2 OFFSET $3`
		args = []any{r.tenantID, limit, offset}
	}

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("pg_shared: list users: %w", err)
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
			return nil, fmt.Errorf("pg_shared: scan user: %w", err)
		}
		if len(metadata) > 0 {
			if err := json.Unmarshal(metadata, &u.Metadata); err != nil {
				log.Printf("WARN: pg_shared: json.Unmarshal metadata for user %s: %v", u.ID, err)
			}
		}
		u.CustomFields = sharedUnmarshalCustomData(customData)
		users = append(users, u)
	}
	return users, rows.Err()
}

func (r *sharedUserRepo) Delete(ctx context.Context, userID string) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		// Delete dependencies in FK-safe order
		depTables := []string{
			"password_history", "webauthn_credential",
			"sessions", "user_consent", "mfa_recovery_code", "mfa_trusted_device", "mfa_totp",
			"password_reset_token", "email_verification_token",
			"rbac_user_role", "refresh_token", "identity",
		}
		for _, table := range depTables {
			if _, err := tx.Exec(ctx,
				fmt.Sprintf("DELETE FROM %s WHERE tenant_id = $1 AND user_id = $2", table),
				r.tenantID, userID,
			); err != nil {
				return fmt.Errorf("delete from %s: %w", table, err)
			}
		}
		tag, err := tx.Exec(ctx, "DELETE FROM app_user WHERE tenant_id = $1 AND id = $2", r.tenantID, userID)
		if err != nil {
			return fmt.Errorf("delete user: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

// ─── sharedIdentityRepo ──────────────────────────────────────────

type sharedIdentityRepo struct {
	pool     *pgxpool.Pool
	tenantID uuid.UUID
}

func (r *sharedIdentityRepo) GetByProvider(ctx context.Context, _ string, provider, providerUserID string) (*repository.SocialIdentity, error) {
	const query = `
		SELECT id, user_id, provider, provider_user_id, email, email_verified, data, created_at, updated_at
		FROM identity
		WHERE tenant_id = $1 AND provider = $2 AND provider_user_id = $3
	`
	var identity repository.SocialIdentity
	var data []byte
	err := r.pool.QueryRow(ctx, query, r.tenantID, provider, providerUserID).Scan(
		&identity.ID, &identity.UserID, &identity.Provider, &identity.ProviderUserID,
		&identity.Email, &identity.EmailVerified, &data,
		&identity.CreatedAt, &identity.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
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
		FROM identity WHERE tenant_id = $1 AND user_id = $2 ORDER BY created_at
	`
	rows, err := r.pool.Query(ctx, query, r.tenantID, userID)
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
	err = execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		// 1. Find existing identity
		var existingIdentityUserID string
		scanErr := tx.QueryRow(ctx,
			`SELECT user_id FROM identity WHERE tenant_id = $1 AND provider = $2 AND provider_user_id = $3`,
			r.tenantID, input.Provider, input.ProviderUserID,
		).Scan(&existingIdentityUserID)

		if scanErr == nil {
			// Identity exists → update and return
			_, updateErr := tx.Exec(ctx, `
				UPDATE identity SET email = $4, email_verified = $5, updated_at = NOW()
				WHERE tenant_id = $1 AND provider = $2 AND provider_user_id = $3`,
				r.tenantID, input.Provider, input.ProviderUserID,
				input.Email, input.EmailVerified,
			)
			if updateErr != nil {
				return updateErr
			}
			userID = existingIdentityUserID
			isNew = false
			return nil
		} else if !errors.Is(scanErr, pgx.ErrNoRows) {
			return scanErr
		}

		// 2. Identity doesn't exist. Find user by email.
		var existingUserID string
		scanErr = tx.QueryRow(ctx,
			`SELECT id FROM app_user WHERE tenant_id = $1 AND email = $2`,
			r.tenantID, input.Email,
		).Scan(&existingUserID)

		if scanErr == nil {
			userID = existingUserID
			isNew = false
		} else if errors.Is(scanErr, pgx.ErrNoRows) {
			// User doesn't exist → create new
			userID = uuid.NewString()
			isNew = true
			now := time.Now()
			_, createErr := tx.Exec(ctx, `
				INSERT INTO app_user (id, tenant_id, email, email_verified, name, picture, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $7)`,
				userID, r.tenantID, input.Email, input.EmailVerified, input.Name, input.Picture, now,
			)
			if createErr != nil {
				return createErr
			}
		} else {
			return scanErr
		}

		// 3. Create identity
		identityID := uuid.NewString()
		now := time.Now()
		_, insertErr := tx.Exec(ctx, `
			INSERT INTO identity (id, tenant_id, user_id, provider, provider_user_id, email, email_verified, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)`,
			identityID, r.tenantID, userID, input.Provider, input.ProviderUserID,
			input.Email, input.EmailVerified, now,
		)
		return insertErr
	})

	return userID, isNew, err
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

	err := execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO identity (id, tenant_id, user_id, provider, provider_user_id, email, email_verified, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)`,
			identityID, r.tenantID, userID, input.Provider, input.ProviderUserID,
			input.Email, input.EmailVerified, now,
		)
		return err
	})
	if err != nil {
		return nil, err
	}
	return identity, nil
}

func (r *sharedIdentityRepo) Unlink(ctx context.Context, userID, provider string) error {
	// Prevent unlinking last identity
	var cnt int
	err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM identity WHERE tenant_id = $1 AND user_id = $2`, r.tenantID, userID,
	).Scan(&cnt)
	if err != nil {
		return err
	}
	if cnt <= 1 {
		return repository.ErrLastIdentity
	}

	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM identity WHERE tenant_id = $1 AND user_id = $2 AND provider = $3`,
			r.tenantID, userID, provider,
		)
		return err
	})
}

func (r *sharedIdentityRepo) UpdateClaims(ctx context.Context, identityID string, claims map[string]any) error {
	return execWithRLS(ctx, r.pool, r.tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE identity SET data = $3, updated_at = NOW() WHERE tenant_id = $1 AND id = $2`,
			r.tenantID, identityID, claims,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}
