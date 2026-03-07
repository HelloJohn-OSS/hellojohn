package middlewares

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

type apiKeyCtxKey struct{}

// APIKeyFromContext recupera la API key validada del context.
// Retorna nil si no hay key (endpoint público o no pasó por autenticación de API key).
func APIKeyFromContext(ctx context.Context) *repository.APIKey {
	v, _ := ctx.Value(apiKeyCtxKey{}).(*repository.APIKey)
	return v
}

// hashAPIKey computes the canonical SHA-256 hash of a raw API key token.
// Used consistently by all auth middlewares to look up keys by hash.
// Format: "sha256:<64 lowercase hex chars>"
func hashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("sha256:%x", sum)
}
