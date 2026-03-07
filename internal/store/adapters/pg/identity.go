// adapters/pg/identity.go — Implementación PostgreSQL de IdentityRepository
// Usa la tabla existente: identity (no social_identity)
package pg

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

type identityRepo struct {
	pool *pgxpool.Pool
}

// newIdentityRepo crea un repositorio de identidades sociales.
func newIdentityRepo(pool *pgxpool.Pool) *identityRepo {
	return &identityRepo{pool: pool}
}

func (r *identityRepo) GetByProvider(ctx context.Context, tenantID, provider, providerUserID string) (*repository.SocialIdentity, error) {
	const query = `
		SELECT id, user_id, provider, provider_user_id, email, email_verified, data, created_at, updated_at
		FROM identity
		WHERE provider = $1 AND provider_user_id = $2
	`
	var identity repository.SocialIdentity
	var data []byte
	err := r.pool.QueryRow(ctx, query, provider, providerUserID).Scan(
		&identity.ID, &identity.UserID, &identity.Provider, &identity.ProviderUserID,
		&identity.Email, &identity.EmailVerified, &data,
		&identity.CreatedAt, &identity.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, repository.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	identity.TenantID = tenantID // tenant implícito por DB
	return &identity, nil
}

func (r *identityRepo) GetByUserID(ctx context.Context, userID string) ([]repository.SocialIdentity, error) {
	const query = `
		SELECT id, user_id, provider, provider_user_id, email, email_verified, data, created_at, updated_at
		FROM identity WHERE user_id = $1 ORDER BY created_at
	`
	rows, err := r.pool.Query(ctx, query, userID)
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
		identities = append(identities, identity)
	}
	return identities, rows.Err()
}

func (r *identityRepo) Upsert(ctx context.Context, input repository.UpsertSocialIdentityInput) (userID string, isNew bool, err error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return "", false, err
	}
	defer tx.Rollback(ctx)

	// 1. Buscar identidad existente
	var existingIdentityUserID string
	err = tx.QueryRow(ctx,
		`SELECT user_id FROM identity WHERE provider = $1 AND provider_user_id = $2`,
		input.Provider, input.ProviderUserID,
	).Scan(&existingIdentityUserID)

	if err == nil {
		// Identidad existe → actualizar y retornar
		_, err = tx.Exec(ctx, `
			UPDATE identity SET email = $3, email_verified = $4, updated_at = NOW()
			WHERE provider = $1 AND provider_user_id = $2`,
			input.Provider, input.ProviderUserID,
			input.Email, input.EmailVerified,
		)
		if err != nil {
			return "", false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return "", false, err
		}
		return existingIdentityUserID, false, nil
	} else if err != pgx.ErrNoRows {
		return "", false, err
	}

	// 2. Identidad no existe. Buscar usuario por email.
	var existingUserID string
	err = tx.QueryRow(ctx,
		`SELECT id FROM app_user WHERE email = $1`,
		input.Email,
	).Scan(&existingUserID)

	if err == nil {
		// Usuario existe → vincular identidad
		userID = existingUserID
		isNew = false
	} else if err == pgx.ErrNoRows {
		// Usuario no existe → crear nuevo
		userID = uuid.NewString()
		isNew = true
		now := time.Now()
		_, err = tx.Exec(ctx, `
			INSERT INTO app_user (id, email, email_verified, name, picture, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $6)`,
			userID, input.Email, input.EmailVerified, input.Name, input.Picture, now,
		)
		if err != nil {
			return "", false, err
		}
	} else {
		return "", false, err
	}

	// 3. Crear identidad
	identityID := uuid.NewString()
	now := time.Now()
	_, err = tx.Exec(ctx, `
		INSERT INTO identity (id, user_id, provider, provider_user_id, email, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $7)`,
		identityID, userID, input.Provider, input.ProviderUserID,
		input.Email, input.EmailVerified, now,
	)
	if err != nil {
		return "", false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return "", false, err
	}

	return userID, isNew, nil
}

func (r *identityRepo) Link(ctx context.Context, userID string, input repository.UpsertSocialIdentityInput) (*repository.SocialIdentity, error) {
	identityID := uuid.NewString()
	now := time.Now()

	identity := &repository.SocialIdentity{
		ID:             identityID,
		UserID:         userID,
		TenantID:       input.TenantID,
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

	_, err := r.pool.Exec(ctx, `
		INSERT INTO identity (id, user_id, provider, provider_user_id, email, email_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $7)`,
		identityID, userID, input.Provider, input.ProviderUserID,
		input.Email, input.EmailVerified, now,
	)
	if err != nil {
		return nil, err
	}

	return identity, nil
}

func (r *identityRepo) Unlink(ctx context.Context, userID, provider string) error {
	// Verificar que no sea la última identidad
	var cnt int
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM identity WHERE user_id = $1`, userID,
	).Scan(&cnt)
	if err != nil {
		return err
	}
	if cnt <= 1 {
		return repository.ErrLastIdentity
	}

	_, err = r.pool.Exec(ctx,
		`DELETE FROM identity WHERE user_id = $1 AND provider = $2`,
		userID, provider,
	)
	return err
}

func (r *identityRepo) UpdateClaims(ctx context.Context, identityID string, claims map[string]any) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE identity SET data = $2, updated_at = NOW() WHERE id = $1`,
		identityID, claims,
	)
	return err
}
