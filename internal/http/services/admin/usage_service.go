package admin

import (
	"context"
	"errors"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// ErrUsageNotAvailable is returned when no global DB is configured and usage metrics
// are therefore unavailable.
var ErrUsageNotAvailable = errors.New("usage metrics not available: no global database configured")

// UsageService expone métricas de uso de tenants.
type UsageService interface {
	GetTenantUsage(ctx context.Context, tenantID string, month time.Time) (*repository.TenantUsageStats, error)
	GetUsageHistory(ctx context.Context, tenantID string, months int) ([]repository.TenantUsageStats, error)
	ListTopTenants(ctx context.Context, month time.Time, limit int) ([]repository.TenantUsageStats, error)
}

// usageService implementación interna.
type usageService struct {
	repo repository.UsageRepository
}

// NewUsageService crea el UsageService.
// repo puede ser nil (cuando no hay global DB configurada) — todos los métodos
// retornarán ErrUsageNotAvailable en ese caso.
func NewUsageService(repo repository.UsageRepository) UsageService {
	return &usageService{repo: repo}
}

func (s *usageService) GetTenantUsage(ctx context.Context, tenantID string, month time.Time) (*repository.TenantUsageStats, error) {
	if s.repo == nil {
		return nil, ErrUsageNotAvailable
	}
	return s.repo.GetUsage(ctx, tenantID, month)
}

func (s *usageService) GetUsageHistory(ctx context.Context, tenantID string, months int) ([]repository.TenantUsageStats, error) {
	if s.repo == nil {
		return nil, ErrUsageNotAvailable
	}
	if months <= 0 {
		months = 6
	}
	return s.repo.GetUsageHistory(ctx, tenantID, months)
}

func (s *usageService) ListTopTenants(ctx context.Context, month time.Time, limit int) ([]repository.TenantUsageStats, error) {
	if s.repo == nil {
		return nil, ErrUsageNotAvailable
	}
	if limit <= 0 {
		limit = 10
	}
	return s.repo.ListTopTenants(ctx, month, limit)
}
