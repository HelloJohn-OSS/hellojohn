// adapters/pg/email_token.go — Implementación PostgreSQL de EmailTokenRepository
// Usa las tablas existentes: email_verification_token y password_reset_token
package pg

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

type emailTokenRepo struct {
	pool *pgxpool.Pool
}

// newEmailTokenRepo crea un repositorio de email tokens.
func newEmailTokenRepo(pool *pgxpool.Pool) *emailTokenRepo {
	return &emailTokenRepo{pool: pool}
}

// tableForType retorna el nombre de tabla según el tipo de token.
func tableForType(t repository.EmailTokenType) string {
	switch t {
	case repository.EmailTokenPasswordReset:
		return "password_reset_token"
	default:
		return "email_verification_token"
	}
}

func (r *emailTokenRepo) Create(ctx context.Context, input repository.CreateEmailTokenInput) (*repository.EmailToken, error) {
	table := tableForType(input.Type)

	// Invalidar tokens previos del mismo usuario
	_, err := r.pool.Exec(ctx,
		`UPDATE `+table+` SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL`,
		input.UserID)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(time.Duration(input.TTLSeconds) * time.Second)
	now := time.Now()

	token := &repository.EmailToken{
		TenantID:  input.TenantID,
		UserID:    input.UserID,
		Email:     input.Email,
		Type:      input.Type,
		TokenHash: input.TokenHash,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}

	query := `
		INSERT INTO ` + table + ` (user_id, token_hash, sent_to, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id
	`
	err = r.pool.QueryRow(ctx, query,
		input.UserID, []byte(input.TokenHash), input.Email, expiresAt, now,
	).Scan(&token.ID)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (r *emailTokenRepo) GetByHash(ctx context.Context, tokenHash string) (*repository.EmailToken, error) {
	// Buscar en ambas tablas
	for _, t := range []repository.EmailTokenType{repository.EmailTokenVerification, repository.EmailTokenPasswordReset} {
		table := tableForType(t)
		query := `
			SELECT id, user_id, sent_to, expires_at, used_at, created_at
			FROM ` + table + ` WHERE token_hash = $1
		`
		var token repository.EmailToken
		token.Type = t
		err := r.pool.QueryRow(ctx, query, []byte(tokenHash)).Scan(
			&token.ID, &token.UserID, &token.Email,
			&token.ExpiresAt, &token.UsedAt, &token.CreatedAt,
		)
		if err == nil {
			token.TokenHash = tokenHash
			return &token, nil
		}
		if err != pgx.ErrNoRows {
			return nil, err
		}
	}
	return nil, repository.ErrNotFound
}

func (r *emailTokenRepo) Use(ctx context.Context, tokenHash string) error {
	// Intentar en ambas tablas
	for _, t := range []repository.EmailTokenType{repository.EmailTokenVerification, repository.EmailTokenPasswordReset} {
		table := tableForType(t)
		query := `
			UPDATE ` + table + ` SET used_at = NOW()
			WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW()
			RETURNING id
		`
		var id string
		err := r.pool.QueryRow(ctx, query, []byte(tokenHash)).Scan(&id)
		if err == nil {
			return nil
		}
		if err != pgx.ErrNoRows {
			return err
		}
	}

	// Verificar si existe pero expiró o ya fue usado
	for _, t := range []repository.EmailTokenType{repository.EmailTokenVerification, repository.EmailTokenPasswordReset} {
		table := tableForType(t)
		var exists bool
		r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+table+` WHERE token_hash = $1)`, []byte(tokenHash)).Scan(&exists)
		if exists {
			return repository.ErrTokenExpired
		}
	}
	return repository.ErrNotFound
}

func (r *emailTokenRepo) DeleteExpired(ctx context.Context) (int, error) {
	var total int
	for _, t := range []repository.EmailTokenType{repository.EmailTokenVerification, repository.EmailTokenPasswordReset} {
		table := tableForType(t)
		query := `DELETE FROM ` + table + ` WHERE expires_at < NOW() OR used_at IS NOT NULL`
		tag, err := r.pool.Exec(ctx, query)
		if err != nil {
			return total, err
		}
		total += int(tag.RowsAffected())
	}
	return total, nil
}
