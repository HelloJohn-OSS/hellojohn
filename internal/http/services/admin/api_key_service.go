package admin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"github.com/google/uuid"
)

// APIKeyService gestiona el ciclo de vida de las API keys.
type APIKeyService interface {
	Create(ctx context.Context, req dto.CreateAPIKeyRequest, createdBy string) (*dto.CreateAPIKeyResult, error)
	List(ctx context.Context) ([]dto.APIKeyInfo, error)
	GetByID(ctx context.Context, id string) (*dto.APIKeyInfo, error)
	Revoke(ctx context.Context, id string) error
	Rotate(ctx context.Context, id string, createdBy string) (*dto.RotateAPIKeyResult, error)
}

// Errores de dominio
var (
	ErrAPIKeyNotFound     = errors.New("api key not found")
	ErrAPIKeyInvalidScope = errors.New("invalid scope")
	ErrAPIKeyNameEmpty    = errors.New("name is required")
	ErrAPIKeyNameTooLong  = errors.New("name exceeds 100 characters")
)

type APIKeyDeps struct {
	Repo repository.APIKeyRepository
}

type apiKeyService struct {
	deps APIKeyDeps
}

func NewAPIKeyService(deps APIKeyDeps) APIKeyService {
	return &apiKeyService{deps: deps}
}

// generateToken genera un token criptográficamente seguro con el formato correcto.
// Retorna: (rawToken, sha256Hash, keyPrefix, error)
func generateToken(scope string) (raw, hash, prefix string, err error) {
	b := make([]byte, 32) // 256 bits de entropía
	if _, err = rand.Read(b); err != nil {
		return "", "", "", fmt.Errorf("generate token: %w", err)
	}
	randomPart := hex.EncodeToString(b) // 64 chars hex

	// Construir el scope prefix del token
	var scopePart string
	switch scope {
	case repository.APIKeyScopeAdmin:
		scopePart = "admin"
	case repository.APIKeyScopeReadOnly:
		scopePart = "ro"
	case repository.APIKeyScopeCloud:
		scopePart = "cloud"
	default:
		if strings.HasPrefix(scope, "tenant:") {
			slug := strings.TrimPrefix(scope, "tenant:")
			// Limitar slug en el prefijo a 20 chars para legibilidad
			if len(slug) > 20 {
				slug = slug[:20]
			}
			scopePart = "t_" + slug
		} else {
			return "", "", "", fmt.Errorf("generate token: invalid scope %q", scope)
		}
	}

	raw = fmt.Sprintf("hj_%s_%s", scopePart, randomPart)

	sum := sha256.Sum256([]byte(raw))
	hash = fmt.Sprintf("sha256:%x", sum)

	// KeyPrefix = primeros 14 chars del token raw (incluye "hj_" + scope discriminador)
	if len(raw) >= 14 {
		prefix = raw[:14]
	} else {
		prefix = raw
	}
	return
}

func (s *apiKeyService) Create(ctx context.Context, req dto.CreateAPIKeyRequest, createdBy string) (*dto.CreateAPIKeyResult, error) {
	// Validaciones
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return nil, ErrAPIKeyNameEmpty
	}
	if len(req.Name) > 100 {
		return nil, ErrAPIKeyNameTooLong
	}
	if !repository.ValidateScope(req.Scope) {
		return nil, ErrAPIKeyInvalidScope
	}

	// Calcular ExpiresAt
	var expiresAt *time.Time
	if req.ExpiresIn != nil {
		d, err := parseDuration(*req.ExpiresIn)
		if err != nil {
			return nil, fmt.Errorf("invalid expires_in: %w", err)
		}
		t := time.Now().UTC().Add(d)
		expiresAt = &t
	}

	raw, hash, prefix, err := generateToken(req.Scope)
	if err != nil {
		return nil, fmt.Errorf("api_key create: %w", err)
	}

	key := repository.APIKey{
		ID:        uuid.NewString(),
		Name:      req.Name,
		KeyPrefix: prefix,
		KeyHash:   hash,
		Scope:     req.Scope,
		CreatedBy: createdBy,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
	}

	if err := s.deps.Repo.Create(ctx, key); err != nil {
		return nil, fmt.Errorf("api_key create: persist: %w", err)
	}

	return &dto.CreateAPIKeyResult{
		ID:        key.ID,
		Name:      key.Name,
		Token:     raw, // UNA SOLA VEZ — después no es recuperable
		KeyPrefix: prefix,
		Scope:     key.Scope,
		ExpiresAt: key.ExpiresAt,
		CreatedAt: key.CreatedAt,
	}, nil
}

func (s *apiKeyService) List(ctx context.Context) ([]dto.APIKeyInfo, error) {
	keys, err := s.deps.Repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("api_key list: %w", err)
	}
	infos := make([]dto.APIKeyInfo, len(keys))
	for i, k := range keys {
		infos[i] = toAPIKeyInfo(k)
	}
	return infos, nil
}

func (s *apiKeyService) GetByID(ctx context.Context, id string) (*dto.APIKeyInfo, error) {
	k, err := s.deps.Repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrAPIKeyNotFound
		}
		return nil, fmt.Errorf("api_key get: %w", err)
	}
	if k == nil {
		return nil, ErrAPIKeyNotFound
	}
	info := toAPIKeyInfo(*k)
	return &info, nil
}

func (s *apiKeyService) Revoke(ctx context.Context, id string) error {
	if err := s.deps.Repo.Revoke(ctx, id); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrAPIKeyNotFound
		}
		return fmt.Errorf("api_key revoke: %w", err)
	}
	return nil
}

func (s *apiKeyService) Rotate(ctx context.Context, id string, createdBy string) (*dto.RotateAPIKeyResult, error) {
	old, err := s.deps.Repo.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrAPIKeyNotFound
		}
		return nil, fmt.Errorf("api_key rotate: get old: %w", err)
	}
	if old == nil {
		return nil, ErrAPIKeyNotFound
	}

	// Rechazar rotación de key ya revocada
	if old.RevokedAt != nil {
		return nil, fmt.Errorf("cannot rotate a revoked API key")
	}

	// Rechazar rotación de key ya expirada
	if old.ExpiresAt != nil && time.Now().UTC().After(*old.ExpiresAt) {
		return nil, fmt.Errorf("api_key rotate: key is already expired")
	}

	// Crear nueva key con los mismos parámetros
	baseName := strings.TrimSuffix(old.Name, " (rotated)")
	newName := baseName + " (rotated)"
	const maxAPIKeyNameLen = 100
	if len(newName) > maxAPIKeyNameLen {
		newName = newName[:maxAPIKeyNameLen-3] + "..."
	}
	newKeyReq := dto.CreateAPIKeyRequest{
		Name:  newName,
		Scope: old.Scope,
	}
	if old.ExpiresAt != nil {
		// Inherit remaining TTL but enforce a minimum of 60s so the new key
		// is not born nearly-expired (M-BACK-5).
		remaining := time.Until(*old.ExpiresAt)
		const minRotateTTL = 60 * time.Second
		if remaining < minRotateTTL {
			remaining = minRotateTTL
		}
		d := remaining.String()
		newKeyReq.ExpiresIn = &d
	}

	newKey, err := s.Create(ctx, newKeyReq, createdBy)
	if err != nil {
		return nil, fmt.Errorf("rotate: create new: %w", err)
	}

	// Revocar la anterior DESPUÉS de crear la nueva (atomicidad best-effort)
	// Si la revocación falla, intentamos revocar la nueva para evitar keys huérfanas.
	if err := s.deps.Repo.Revoke(ctx, id); err != nil {
		if rbErr := s.deps.Repo.Revoke(ctx, newKey.ID); rbErr != nil {
			// Both revocations failed — two keys may be simultaneously active.
			// Log at ERROR level so operators can take manual action.
			logger.From(ctx).Error("api_key rotate: failed to revoke new key after old key revoke failure; both keys may be active",
				logger.String("new_key_id", newKey.ID),
				logger.Err(err),
			)
		}
		return nil, fmt.Errorf("rotate: revoke old: %w", err)
	}

	return &dto.RotateAPIKeyResult{
		OldKeyID: id,
		NewKey:   *newKey,
	}, nil
}

func toAPIKeyInfo(k repository.APIKey) dto.APIKeyInfo {
	return dto.APIKeyInfo{
		ID: k.ID, Name: k.Name, KeyPrefix: k.KeyPrefix,
		Scope: k.Scope, CreatedBy: k.CreatedBy,
		CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt,
		ExpiresAt: k.ExpiresAt, RevokedAt: k.RevokedAt,
		IsActive: k.IsActive(),
	}
}

// parseDuration extiende time.ParseDuration con soporte para sufijos "d" (días).
// Ejemplos válidos: "7d", "30d", "24h", "1h30m".
func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid duration %q: days must be a positive integer", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration must be positive, got %s", s)
	}
	return d, nil
}
