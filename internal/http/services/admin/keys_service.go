package admin

import (
	"context"
	"fmt"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// KeysService define operaciones de gestión de claves admin.
type KeysService interface {
	ListKeys(ctx context.Context, tenantID string) ([]dto.KeyInfoDTO, error)
	GetKey(ctx context.Context, kid string) (*dto.KeyDetailsDTO, error)
	RotateKeys(ctx context.Context, tenantID string, graceSeconds int64) (*dto.RotateResult, error)
	RevokeKey(ctx context.Context, kid string) error
}

type keysService struct {
	dal store.DataAccessLayer
}

// NewKeysService crea un nuevo servicio de claves.
func NewKeysService(dal store.DataAccessLayer) KeysService {
	return &keysService{dal: dal}
}

func (s *keysService) ListKeys(ctx context.Context, tenantID string) ([]dto.KeyInfoDTO, error) {
	keyRepo := s.dal.ConfigAccess().Keys()

	keys, err := keyRepo.ListAll(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list keys: %w", err)
	}

	dtos := make([]dto.KeyInfoDTO, len(keys))
	for i, key := range keys {
		dtos[i] = s.toKeyInfoDTO(key)
	}
	return dtos, nil
}

func (s *keysService) GetKey(ctx context.Context, kid string) (*dto.KeyDetailsDTO, error) {
	keyRepo := s.dal.ConfigAccess().Keys()

	key, err := keyRepo.GetByKID(ctx, kid)
	if err != nil {
		return nil, err
	}

	info := s.toKeyInfoDTO(key)
	return &dto.KeyDetailsDTO{KeyInfoDTO: info}, nil
}

func (s *keysService) RotateKeys(ctx context.Context, tenantID string, graceSeconds int64) (*dto.RotateResult, error) {
	keyRepo := s.dal.ConfigAccess().Keys()

	gracePeriod := time.Duration(graceSeconds) * time.Second
	newKey, err := keyRepo.Rotate(ctx, tenantID, gracePeriod)
	if err != nil {
		return nil, fmt.Errorf("rotate keys: %w", err)
	}

	return &dto.RotateResult{
		KID:          newKey.ID,
		GraceSeconds: graceSeconds,
		Message:      "Key rotation successful",
	}, nil
}

func (s *keysService) RevokeKey(ctx context.Context, kid string) error {
	keyRepo := s.dal.ConfigAccess().Keys()
	return keyRepo.Revoke(ctx, kid)
}

func (s *keysService) toKeyInfoDTO(key *repository.SigningKey) dto.KeyInfoDTO {
	d := dto.KeyInfoDTO{
		KID:       key.ID,
		Algorithm: key.Algorithm,
		Use:       "sig",
		Status:    string(key.Status),
		CreatedAt: key.CreatedAt.Format(time.RFC3339),
		TenantID:  key.TenantID,
	}
	if key.RetiredAt != nil {
		retiredStr := key.RetiredAt.Format(time.RFC3339)
		d.RetiredAt = &retiredStr
	}
	return d
}
