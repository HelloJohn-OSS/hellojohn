package admin

import (
	"context"
	"errors"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
)

// ErrPushTenantNotAvailable indicates that tenant push is disabled in OSS.
var ErrPushTenantNotAvailable = errors.New("tenant push is cloud-only and disabled in OSS")

// PushTenant is intentionally disabled in OSS builds.
func (s *tenantsService) PushTenant(ctx context.Context, slugOrID string, req dto.PushTenantRequest) (*dto.PushTenantResponse, error) {
	return nil, ErrPushTenantNotAvailable
}
