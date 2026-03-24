// Package pg implementa el adapter PostgreSQL para store/v2.
// Usa pgxpool directamente, sin dependencias de store/v1.
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	secpassword "github.com/dropDatabas3/hellojohn/internal/security/password"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

func init() {
	store.RegisterAdapter(&postgresAdapter{})
}

// nullIfEmpty returns nil if the string is empty, otherwise returns the string pointer.
// Useful for inserting optional string fields into PostgreSQL.
func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// pgIdentifier sanitizes a string to be used as a PostgreSQL identifier.
// Only allows alphanumeric characters and underscores.
var validIdentifier = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,58}$`)

// pgIdentifier normalizes and validates a string to be used as a PostgreSQL identifier.
// Converts spaces to underscores, removes accents, and validates the result.
func pgIdentifier(name string) string {
	// Normalize: lowercase, trim, replace spaces with underscores
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.ReplaceAll(name, " ", "_")

	// Remove accents and special characters (keep only a-z, 0-9, _)
	var normalized strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			normalized.WriteRune(r)
		case r >= '0' && r <= '9':
			normalized.WriteRune(r)
		case r == '_':
			normalized.WriteRune(r)
		// Common accented characters -> base letter
		case r == 'á' || r == 'à' || r == 'ä' || r == 'â' || r == 'ã':
			normalized.WriteRune('a')
		case r == 'é' || r == 'è' || r == 'ë' || r == 'ê':
			normalized.WriteRune('e')
		case r == 'í' || r == 'ì' || r == 'ï' || r == 'î':
			normalized.WriteRune('i')
		case r == 'ó' || r == 'ò' || r == 'ö' || r == 'ô' || r == 'õ':
			normalized.WriteRune('o')
		case r == 'ú' || r == 'ù' || r == 'ü' || r == 'û':
			normalized.WriteRune('u')
		case r == 'ñ':
			normalized.WriteRune('n')
		case r == 'ç':
			normalized.WriteRune('c')
			// Skip other characters
		}
	}
	name = normalized.String()

	// Ensure it doesn't start with a number
	if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
		name = "_" + name
	}

	// Final validation
	if !validIdentifier.MatchString(name) || name == "" {
		return ""
	}
	return name
}

// isSystemColumn returns true if the column is a system column (not a custom field).
func isSystemColumn(name string) bool {
	switch name {
	case "id", "tenant_id", "email", "email_verified", "status", "profile", "metadata",
		"disabled_at", "disabled_reason", "disabled_until",
		"created_at", "updated_at", "password_hash",
		"name", "given_name", "family_name", "picture", "locale", "language", "source_client_id",
		"custom_data":
		return true
	}
	return false
}

// postgresAdapter implementa store.Adapter para PostgreSQL.
type postgresAdapter struct{}

func (a *postgresAdapter) Name() string { return "postgres" }

func (a *postgresAdapter) Connect(ctx context.Context, cfg store.AdapterConfig) (store.AdapterConnection, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("pg: parse DSN: %w", err)
	}

	// Configurar pool
	if cfg.MaxOpenConns > 0 {
		poolCfg.MaxConns = int32(cfg.MaxOpenConns)
	} else {
		poolCfg.MaxConns = 10
	}
	if cfg.MaxIdleConns > 0 {
		poolCfg.MinConns = int32(cfg.MaxIdleConns)
	} else {
		poolCfg.MinConns = 2
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("pg: create pool: %w", err)
	}

	// Verificar conexión
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pg: ping failed: %w", err)
	}

	return &pgConnection{pool: pool, schema: cfg.Schema}, nil
}

// pgConnection representa una conexión activa a PostgreSQL.
type pgConnection struct {
	pool   *pgxpool.Pool
	schema string
}

func (c *pgConnection) Name() string { return "postgres" }

func (c *pgConnection) Ping(ctx context.Context) error {
	return c.pool.Ping(ctx)
}

func (c *pgConnection) Close() error {
	c.pool.Close()
	return nil
}

// ─── Repositorios ───

func (c *pgConnection) Users() repository.UserRepository       { return &userRepo{pool: c.pool} }
func (c *pgConnection) Tokens() repository.TokenRepository     { return &tokenRepo{pool: c.pool} }
func (c *pgConnection) MFA() repository.MFARepository          { return &mfaRepo{pool: c.pool} }
func (c *pgConnection) Consents() repository.ConsentRepository { return &consentRepo{pool: c.pool} }
func (c *pgConnection) Scopes() repository.ScopeRepository     { return &scopeRepo{pool: c.pool} }
func (c *pgConnection) RBAC() repository.RBACRepository        { return &rbacRepo{pool: c.pool} }
func (c *pgConnection) Schema() repository.SchemaRepository    { return &pgSchemaRepo{conn: c} }
func (c *pgConnection) EmailTokens() repository.EmailTokenRepository {
	return newEmailTokenRepo(c.pool)
}
func (c *pgConnection) Identities() repository.IdentityRepository { return newIdentityRepo(c.pool) }
func (c *pgConnection) Sessions() repository.SessionRepository    { return NewSessionRepo(c.pool) }
func (c *pgConnection) Audit() repository.AuditRepository         { return &auditRepo{pool: c.pool} }
func (c *pgConnection) Webhooks() repository.WebhookRepository    { return &webhookRepo{pool: c.pool} }
func (c *pgConnection) Invitations() repository.InvitationRepository {
	return &invitationRepo{pool: c.pool}
}
func (c *pgConnection) WebAuthn() repository.WebAuthnRepository { return &webAuthnRepo{pool: c.pool} }

// Control plane — repos sobre la Global DB (cp_* tables)
func (c *pgConnection) Tenants() repository.TenantRepository {
	return &cpTenantRepo{pool: c.pool}
}
func (c *pgConnection) SystemSettings() repository.SystemSettingsRepository {
	return &pgSystemSettingsRepo{pool: c.pool}
}
func (c *pgConnection) Admins() repository.AdminRepository {
	return &cpAdminRepo{pool: c.pool}
}
func (c *pgConnection) AdminRefreshTokens() repository.AdminRefreshTokenRepository {
	return &cpAdminRefreshTokenRepo{pool: c.pool}
}
func (c *pgConnection) Keys() repository.KeyRepository                     { return nil } // Keys viven en FS
func (c *pgConnection) APIKeys() repository.APIKeyRepository               { return nil } // API Keys viven en FS
func (c *pgConnection) CloudUsers() repository.CloudUserRepository         { return nil }
func (c *pgConnection) CloudInstances() repository.CloudInstanceRepository { return nil }

// GetMigrationExecutor implementa store.MigratableConnection.
// Retorna un wrapper del pool para migraciones.
func (c *pgConnection) GetMigrationExecutor() store.PgxPoolExecutor {
	return &pgxPoolWrapper{pool: c.pool}
}

// pgxPoolWrapper adapta pgxpool.Pool a store.PgxPoolExecutor.
type pgxPoolWrapper struct {
	pool *pgxpool.Pool
}

func (w *pgxPoolWrapper) Exec(ctx context.Context, sql string, args ...any) (interface{ RowsAffected() int64 }, error) {
	return w.pool.Exec(ctx, sql, args...)
}

func (w *pgxPoolWrapper) QueryRow(ctx context.Context, sql string, args ...any) interface{ Scan(dest ...any) error } {
	return w.pool.QueryRow(ctx, sql, args...)
}

// ─── UserRepository ───

type userRepo struct{ pool *pgxpool.Pool }

func (r *userRepo) GetByEmail(ctx context.Context, tenantID, email string) (*repository.User, *repository.Identity, error) {
	const query = `
		SELECT u.id, u.email, u.email_verified,
		       COALESCE(u.name, ''), COALESCE(u.given_name, ''), COALESCE(u.family_name, ''),
		       COALESCE(u.picture, ''), COALESCE(u.locale, ''), COALESCE(u.language, ''),
		       u.source_client_id, u.created_at, u.metadata, u.custom_data,
		       u.disabled_at, u.disabled_until, u.disabled_reason,
		       i.id, i.provider, i.provider_user_id, i.email, i.email_verified, i.password_hash, i.created_at
		FROM app_user u
		LEFT JOIN identity i ON i.user_id = u.id AND i.provider = 'password'
		WHERE u.email = $1
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

	user.TenantID = tenantID

	err := r.pool.QueryRow(ctx, query, email).Scan(
		&user.ID, &user.Email, &user.EmailVerified,
		&user.Name, &user.GivenName, &user.FamilyName, &user.Picture, &user.Locale, &user.Language,
		&user.SourceClientID, &user.CreatedAt, &metadata, &customData,
		&user.DisabledAt, &user.DisabledUntil, &user.DisabledReason,
		&identityID, &identityProvider, &identityProviderUserID,
		&identityEmail, &identityEmailVerified, &pwdHash, &identityCreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("pg: get user by email: %w", err)
	}

	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &user.Metadata); err != nil {
			log.Printf("WARN: pg: json.Unmarshal metadata for user %s: %v", user.Email, err)
		}
	}
	user.CustomFields = unmarshalCustomData(customData)

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

func (r *userRepo) GetByID(ctx context.Context, userID string) (*repository.User, error) {
	const query = `
		SELECT id, email, email_verified,
		       COALESCE(name, ''), COALESCE(given_name, ''), COALESCE(family_name, ''),
		       COALESCE(picture, ''), COALESCE(locale, ''), COALESCE(language, ''),
		       source_client_id, created_at, metadata, custom_data,
		       disabled_at, disabled_until, disabled_reason
		FROM app_user WHERE id = $1
	`
	var user repository.User
	var metadata []byte
	var customData []byte

	err := r.pool.QueryRow(ctx, query, userID).Scan(
		&user.ID, &user.Email, &user.EmailVerified,
		&user.Name, &user.GivenName, &user.FamilyName, &user.Picture, &user.Locale, &user.Language,
		&user.SourceClientID, &user.CreatedAt, &metadata, &customData,
		&user.DisabledAt, &user.DisabledUntil, &user.DisabledReason,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("pg: get user by id: %w", err)
	}

	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &user.Metadata); err != nil {
			log.Printf("WARN: pg: json.Unmarshal metadata for user %s: %v", user.ID, err)
		}
	}
	user.CustomFields = unmarshalCustomData(customData)

	return &user, nil
}

// unmarshalCustomData deserializes the custom_data JSONB column into a map.
// Returns an empty (non-nil) map on NULL or invalid JSON.
func unmarshalCustomData(data []byte) map[string]any {
	result := make(map[string]any)
	if len(data) == 0 {
		return result
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return make(map[string]any)
	}
	return result
}

func (r *userRepo) Create(ctx context.Context, input repository.CreateUserInput) (*repository.User, *repository.Identity, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("pg: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	user := &repository.User{
		TenantID:     input.TenantID,
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
		INSERT INTO app_user (email, email_verified, name, given_name, family_name, picture, locale, source_client_id, custom_data, created_at)
		VALUES ($1, false, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id
	`
	err = tx.QueryRow(ctx, insertUser,
		user.Email, nullIfEmpty(input.Name), nullIfEmpty(input.GivenName),
		nullIfEmpty(input.FamilyName), nullIfEmpty(input.Picture), nullIfEmpty(input.Locale),
		user.SourceClientID, customData, user.CreatedAt,
	).Scan(&user.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("pg: insert user: %w", err)
	}

	identity := &repository.Identity{
		UserID:       user.ID,
		Provider:     "password",
		Email:        input.Email,
		PasswordHash: &input.PasswordHash,
		CreatedAt:    time.Now(),
	}

	const insertIdentity = `
		INSERT INTO identity (user_id, provider, email, email_verified, password_hash, created_at)
		VALUES ($1, $2, $3, false, $4, $5)
		RETURNING id
	`
	err = tx.QueryRow(ctx, insertIdentity,
		identity.UserID, identity.Provider, identity.Email, input.PasswordHash, identity.CreatedAt,
	).Scan(&identity.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("pg: insert identity: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("pg: commit tx: %w", err)
	}

	return user, identity, nil
}

func (r *userRepo) CreateBatch(ctx context.Context, tenantID string, users []repository.CreateUserInput) (created, failed int, err error) {
	// CreateBatch delegates to Create per-user. Each Create uses custom_data JSONB.
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

func (r *userRepo) Update(ctx context.Context, userID string, input repository.UpdateUserInput) error {
	setClauses := []string{}
	args := []any{userID}
	argIdx := 2

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

	// Merge custom fields into the JSONB column (shallow merge via ||)
	if len(input.CustomFields) > 0 {
		setClauses = append(setClauses, fmt.Sprintf("custom_data = COALESCE(custom_data, '{}'::jsonb) || $%d::jsonb", argIdx))
		args = append(args, input.CustomFields)
		argIdx++
	}

	if len(setClauses) == 0 {
		return nil
	}

	// Always touch updated_at
	setClauses = append(setClauses, "updated_at = NOW()")

	query := fmt.Sprintf("UPDATE app_user SET %s WHERE id = $1", strings.Join(setClauses, ", "))
	_, err := r.pool.Exec(ctx, query, args...)
	return err
}

func (r *userRepo) Disable(ctx context.Context, userID, by, reason string, until *time.Time) error {
	const query = `
		UPDATE app_user SET
			disabled_at = NOW(),
			disabled_until = $2,
			disabled_reason = $3
		WHERE id = $1
	`
	_, err := r.pool.Exec(ctx, query, userID, until, reason)
	return err
}

func (r *userRepo) Enable(ctx context.Context, userID, by string) error {
	const query = `
		UPDATE app_user SET
			disabled_at = NULL,
			disabled_until = NULL,
			disabled_reason = NULL
		WHERE id = $1
	`
	_, err := r.pool.Exec(ctx, query, userID)
	return err
}

func (r *userRepo) CheckPassword(hash *string, plain string) bool {
	if hash == nil || strings.TrimSpace(*hash) == "" {
		return false
	}
	return secpassword.Verify(plain, *hash)
}

func (r *userRepo) SetEmailVerified(ctx context.Context, userID string, verified bool) error {
	const query = `UPDATE app_user SET email_verified = $2 WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, userID, verified)
	return err
}

func (r *userRepo) UpdatePasswordHash(ctx context.Context, userID, newHash string) error {
	return r.RotatePasswordHash(ctx, userID, newHash, 0)
}

func (r *userRepo) ListPasswordHistory(ctx context.Context, userID string, limit int) ([]string, error) {
	if limit <= 0 {
		return []string{}, nil
	}

	history := make([]string, 0, limit)
	var currentHash string
	if err := r.pool.QueryRow(ctx,
		`SELECT password_hash FROM identity WHERE user_id = $1 AND provider = 'password'`,
		userID,
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
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`
	rows, err := r.pool.Query(ctx, query, userID, remaining)
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

func (r *userRepo) RotatePasswordHash(ctx context.Context, userID, newHash string, keepHistory int) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var currentHash string
	err = tx.QueryRow(ctx,
		`SELECT password_hash FROM identity WHERE user_id = $1 AND provider = 'password' FOR UPDATE`,
		userID,
	).Scan(&currentHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		return err
	}

	if keepHistory > 0 && strings.TrimSpace(currentHash) != "" {
		_, err = tx.Exec(ctx, `
			INSERT INTO password_history (id, user_id, hash, algorithm, created_at)
			VALUES ($1, $2, $3, $4, NOW())
		`, uuid.NewString(), userID, currentHash, "argon2id")
		if err != nil {
			return err
		}
	}

	tag, err := tx.Exec(ctx,
		`UPDATE identity SET password_hash = $2, updated_at = NOW() WHERE user_id = $1 AND provider = 'password'`,
		userID, newHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	if keepHistory > 0 {
		rows, err := tx.Query(ctx, `
			SELECT id
			FROM password_history
			WHERE user_id = $1
			ORDER BY created_at DESC
			OFFSET $2
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
			if _, err := tx.Exec(ctx, `DELETE FROM password_history WHERE user_id = $1 AND id = $2`, userID, staleID); err != nil {
				return err
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	return nil
}

func (r *userRepo) List(ctx context.Context, tenantID string, filter repository.ListUsersFilter) ([]repository.User, error) {
	// Defaults y clamp
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

	var baseQuery string
	var args []any

	const selectCols = `id, email, email_verified, COALESCE(name,''), COALESCE(given_name,''), COALESCE(family_name,''),
		COALESCE(picture,''), COALESCE(locale,''), COALESCE(language,''),
		source_client_id, created_at, metadata, custom_data,
		disabled_at, disabled_until, disabled_reason`

	if filter.Search != "" {
		baseQuery = `SELECT ` + selectCols + ` FROM app_user WHERE (email ILIKE $1 OR name ILIKE $1) ORDER BY created_at DESC LIMIT $2 OFFSET $3`
		args = []any{"%" + filter.Search + "%", limit, offset}
	} else {
		baseQuery = `SELECT ` + selectCols + ` FROM app_user ORDER BY created_at DESC LIMIT $1 OFFSET $2`
		args = []any{limit, offset}
	}

	rows, err := r.pool.Query(ctx, baseQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("pg: list users: %w", err)
	}
	defer rows.Close()

	var users []repository.User
	for rows.Next() {
		var u repository.User
		var metadata []byte
		var customData []byte
		u.TenantID = tenantID

		if err := rows.Scan(
			&u.ID, &u.Email, &u.EmailVerified,
			&u.Name, &u.GivenName, &u.FamilyName, &u.Picture, &u.Locale, &u.Language,
			&u.SourceClientID, &u.CreatedAt, &metadata, &customData,
			&u.DisabledAt, &u.DisabledUntil, &u.DisabledReason,
		); err != nil {
			return nil, fmt.Errorf("pg: scan user: %w", err)
		}

		if len(metadata) > 0 {
			if err := json.Unmarshal(metadata, &u.Metadata); err != nil {
				log.Printf("WARN: pg: json.Unmarshal metadata for user %s: %v", u.ID, err)
			}
		}
		u.CustomFields = unmarshalCustomData(customData)
		users = append(users, u)
	}

	return users, rows.Err()
}

func (r *userRepo) Delete(ctx context.Context, userID string) error {
	// TX para borrar dependencias y usuario
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("pg: begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Helper para ejecutar DELETE parametrizado solo si la tabla y columna user_id existen.
	// En PostgreSQL, incluso errores "esperados" como undefined_table abortan la transacción.
	// Por eso validamos existencia antes de ejecutar el DELETE.
	hasUserIDColumn := func(table string) (bool, error) {
		const query = `
			SELECT EXISTS (
				SELECT 1
				FROM information_schema.columns
				WHERE table_schema = current_schema()
				  AND table_name = $1
				  AND column_name = 'user_id'
			)
		`
		var exists bool
		if err := tx.QueryRow(ctx, query, table).Scan(&exists); err != nil {
			return false, fmt.Errorf("pg: inspect table %s: %w", table, err)
		}
		return exists, nil
	}

	// Las tablas se toman de una lista fija interna (no input de usuario).
	safeDelete := func(table string) error {
		exists, err := hasUserIDColumn(table)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}

		query := fmt.Sprintf(`DELETE FROM %s WHERE user_id = $1`, table)
		_, err = tx.Exec(ctx, query, userID)
		if err == nil {
			return nil
		}

		return fmt.Errorf("pg: delete from %s: %w", table, err)
	}

	// Borrar dependencias de forma segura (incluye aliases legacy y nuevos)
	dependencyTables := []string{
		"identity",
		"refresh_token",
		"user_consent",
		"mfa_totp",
		"user_mfa_totp",
		"mfa_recovery_code",
		"mfa_trusted_device",
		"trusted_device",
		"rbac_user_role",
		"user_role",
		"sessions",
		"email_verification_token",
		"password_reset_token",
		"password_history",
	}
	for _, table := range dependencyTables {
		if err := safeDelete(table); err != nil {
			return err
		}
	}

	// Borrar usuario (esta tabla debe existir)
	tag, err := tx.Exec(ctx, `DELETE FROM app_user WHERE id = $1`, userID)
	if err != nil {
		return fmt.Errorf("pg: delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return repository.ErrNotFound
	}

	return tx.Commit(ctx)
}

// ─── TokenRepository ───

type tokenRepo struct{ pool *pgxpool.Pool }

func (r *tokenRepo) Create(ctx context.Context, input repository.CreateRefreshTokenInput) (string, error) {
	// Note: tenant_id is not stored in DB since each tenant has isolated DB
	const query = `
		INSERT INTO refresh_token (user_id, client_id_text, token_hash, issued_at, expires_at, rotated_from)
		VALUES ($1, $2, $3, NOW(), NOW() + $4::interval, $5)
		RETURNING id
	`
	ttl := fmt.Sprintf("%d seconds", input.TTLSeconds)
	var id string
	err := r.pool.QueryRow(ctx, query,
		input.UserID, input.ClientID, input.TokenHash, ttl, input.RotatedFrom,
	).Scan(&id)
	return id, err
}

func (r *tokenRepo) GetByHash(ctx context.Context, tokenHash string) (*repository.RefreshToken, error) {
	const query = `
		SELECT id, user_id, client_id_text, token_hash, issued_at, expires_at, rotated_from, revoked_at
		FROM refresh_token WHERE token_hash = $1
	`
	var token repository.RefreshToken
	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(
		&token.ID, &token.UserID, &token.ClientID,
		&token.TokenHash, &token.IssuedAt, &token.ExpiresAt, &token.RotatedFrom, &token.RevokedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	// TenantID should be set by the caller from the context/TDA
	return &token, err
}

func (r *tokenRepo) Revoke(ctx context.Context, tokenID string) error {
	const query = `UPDATE refresh_token SET revoked_at = NOW() WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, tokenID)
	return err
}

func (r *tokenRepo) GetFamilyRoot(ctx context.Context, tokenID string) (string, error) {
	const query = `SELECT rotated_from FROM refresh_token WHERE id = $1`
	current := tokenID

	for i := 0; i < 256; i++ {
		var parent *string
		if err := r.pool.QueryRow(ctx, query, current).Scan(&parent); err != nil {
			if err == pgx.ErrNoRows {
				return "", repository.ErrNotFound
			}
			return "", err
		}
		if parent == nil || *parent == "" {
			return current, nil
		}
		current = *parent
	}

	return "", fmt.Errorf("pg: refresh token family chain too deep")
}

func (r *tokenRepo) RevokeFamily(ctx context.Context, familyRootID string) error {
	const query = `
		WITH RECURSIVE family AS (
			SELECT id FROM refresh_token WHERE id = $1
			UNION ALL
			SELECT rt.id
			FROM refresh_token rt
			INNER JOIN family f ON rt.rotated_from = f.id
		)
		UPDATE refresh_token
		SET revoked_at = NOW()
		WHERE id IN (SELECT id FROM family) AND revoked_at IS NULL
	`
	_, err := r.pool.Exec(ctx, query, familyRootID)
	return err
}

func (r *tokenRepo) RevokeAllByUser(ctx context.Context, userID, clientID string) (int, error) {
	var query string
	var args []any
	if clientID != "" {
		query = `UPDATE refresh_token SET revoked_at = NOW() WHERE user_id = $1 AND client_id_text = $2 AND revoked_at IS NULL`
		args = []any{userID, clientID}
	} else {
		query = `UPDATE refresh_token SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`
		args = []any{userID}
	}
	tag, err := r.pool.Exec(ctx, query, args...)
	return int(tag.RowsAffected()), err
}

func (r *tokenRepo) RevokeAllByClient(ctx context.Context, clientID string) error {
	const query = `UPDATE refresh_token SET revoked_at = NOW() WHERE client_id_text = $1 AND revoked_at IS NULL`
	_, err := r.pool.Exec(ctx, query, clientID)
	return err
}

// ─── Admin Token Operations ───

func (r *tokenRepo) GetByID(ctx context.Context, tokenID string) (*repository.RefreshToken, error) {
	const query = `
		SELECT t.id, t.user_id, t.client_id_text, t.token_hash, t.issued_at, t.expires_at, t.rotated_from, t.revoked_at,
		       COALESCE(u.email, '') AS user_email
		FROM refresh_token t
		LEFT JOIN app_user u ON u.id = t.user_id
		WHERE t.id = $1
	`
	var token repository.RefreshToken
	err := r.pool.QueryRow(ctx, query, tokenID).Scan(
		&token.ID, &token.UserID, &token.ClientID,
		&token.TokenHash, &token.IssuedAt, &token.ExpiresAt, &token.RotatedFrom, &token.RevokedAt,
		&token.UserEmail,
	)
	if err == pgx.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	return &token, err
}

func (r *tokenRepo) List(ctx context.Context, filter repository.ListTokensFilter) ([]repository.RefreshToken, error) {
	// Validar paginación
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
		LEFT JOIN app_user u ON u.id = t.user_id
		WHERE 1=1
	`
	args := []any{}
	argIndex := 1

	// Filtro por user_id
	if filter.UserID != nil && *filter.UserID != "" {
		query += fmt.Sprintf(" AND t.user_id = $%d", argIndex)
		args = append(args, *filter.UserID)
		argIndex++
	}

	// Filtro por client_id
	if filter.ClientID != nil && *filter.ClientID != "" {
		query += fmt.Sprintf(" AND t.client_id_text = $%d", argIndex)
		args = append(args, *filter.ClientID)
		argIndex++
	}

	// Filtro por status
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

	// Filtro por búsqueda (email)
	if filter.Search != nil && *filter.Search != "" {
		query += fmt.Sprintf(" AND u.email ILIKE $%d", argIndex)
		args = append(args, "%"+*filter.Search+"%")
		argIndex++
	}

	// Ordenar y paginar
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
		tokens = append(tokens, token)
	}

	return tokens, rows.Err()
}

func (r *tokenRepo) Count(ctx context.Context, filter repository.ListTokensFilter) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM refresh_token t
		LEFT JOIN app_user u ON u.id = t.user_id
		WHERE 1=1
	`
	args := []any{}
	argIndex := 1

	// Filtro por user_id
	if filter.UserID != nil && *filter.UserID != "" {
		query += fmt.Sprintf(" AND t.user_id = $%d", argIndex)
		args = append(args, *filter.UserID)
		argIndex++
	}

	// Filtro por client_id
	if filter.ClientID != nil && *filter.ClientID != "" {
		query += fmt.Sprintf(" AND t.client_id_text = $%d", argIndex)
		args = append(args, *filter.ClientID)
		argIndex++
	}

	// Filtro por status
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

	// Filtro por búsqueda (email)
	if filter.Search != nil && *filter.Search != "" {
		query += fmt.Sprintf(" AND u.email ILIKE $%d", argIndex)
		args = append(args, "%"+*filter.Search+"%")
	}

	var count int
	err := r.pool.QueryRow(ctx, query, args...).Scan(&count)
	return count, err
}

func (r *tokenRepo) RevokeAll(ctx context.Context) (int, error) {
	const query = `UPDATE refresh_token SET revoked_at = NOW() WHERE revoked_at IS NULL`
	tag, err := r.pool.Exec(ctx, query)
	return int(tag.RowsAffected()), err
}

func (r *tokenRepo) GetStats(ctx context.Context) (*repository.TokenStats, error) {
	stats := &repository.TokenStats{}

	// Total activos
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM refresh_token 
		WHERE revoked_at IS NULL AND expires_at > NOW()
	`).Scan(&stats.TotalActive)
	if err != nil {
		return nil, err
	}

	// Emitidos hoy
	err = r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM refresh_token 
		WHERE issued_at >= CURRENT_DATE
	`).Scan(&stats.IssuedToday)
	if err != nil {
		return nil, err
	}

	// Revocados hoy
	err = r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM refresh_token 
		WHERE revoked_at >= CURRENT_DATE
	`).Scan(&stats.RevokedToday)
	if err != nil {
		return nil, err
	}

	// Tiempo de vida promedio (en horas)
	err = r.pool.QueryRow(ctx, `
		SELECT COALESCE(
			AVG(EXTRACT(EPOCH FROM (
				COALESCE(revoked_at, LEAST(expires_at, NOW())) - issued_at
			)) / 3600.0), 0
		)
		FROM refresh_token 
		WHERE revoked_at IS NOT NULL OR expires_at <= NOW()
	`).Scan(&stats.AvgLifetimeHours)
	if err != nil {
		return nil, err
	}

	// Por client (top 10)
	rows, err := r.pool.Query(ctx, `
		SELECT client_id_text, COUNT(*) as cnt
		FROM refresh_token
		WHERE revoked_at IS NULL AND expires_at > NOW()
		GROUP BY client_id_text
		ORDER BY cnt DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var cc repository.ClientTokenCount
		if err := rows.Scan(&cc.ClientID, &cc.Count); err != nil {
			return nil, err
		}
		stats.ByClient = append(stats.ByClient, cc)
	}

	return stats, rows.Err()
}
