package admin

import (
	"context"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// AuditService defines operations for audit log management.
type AuditService interface {
	List(ctx context.Context, tenantSlug string, filter repository.AuditFilter) ([]audit.AuditEvent, int64, error)
	GetByID(ctx context.Context, tenantSlug string, id string) (*audit.AuditEvent, error)
	Purge(ctx context.Context, tenantSlug string, before time.Time) (int64, error)
}

// auditService implements AuditService.
type auditService struct {
	dal      store.DataAccessLayer
	auditBus *audit.AuditBus
}

// NewAuditService creates a new AuditService.
func NewAuditService(dal store.DataAccessLayer, auditBus *audit.AuditBus) AuditService {
	return &auditService{
		dal:      dal,
		auditBus: auditBus,
	}
}

// List returns audit events matching the filter.
func (s *auditService) List(ctx context.Context, tenantSlug string, filter repository.AuditFilter) ([]audit.AuditEvent, int64, error) {
	tda, err := s.dal.ForTenant(ctx, tenantSlug)
	if err != nil {
		return nil, 0, err
	}
	if err := tda.RequireDB(); err != nil {
		return nil, 0, err
	}
	return tda.Audit().List(ctx, filter)
}

// GetByID returns a single audit event by ID.
func (s *auditService) GetByID(ctx context.Context, tenantSlug string, id string) (*audit.AuditEvent, error) {
	tda, err := s.dal.ForTenant(ctx, tenantSlug)
	if err != nil {
		return nil, err
	}
	if err := tda.RequireDB(); err != nil {
		return nil, err
	}
	return tda.Audit().GetByID(ctx, id)
}

// Purge deletes audit events older than the given time.
func (s *auditService) Purge(ctx context.Context, tenantSlug string, before time.Time) (int64, error) {
	tda, err := s.dal.ForTenant(ctx, tenantSlug)
	if err != nil {
		emitAdminEventWithCanonicalTenantRef(ctx, s.auditBus, s.dal, tenantSlug, audit.EventAuditPurged, "", audit.TargetTenant, audit.ResultError, map[string]any{
			"reason": "tenant_resolve_failed",
			"before": before.Format(time.RFC3339),
		})
		return 0, err
	}
	if err := tda.RequireDB(); err != nil {
		emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventAuditPurged, tda.ID(), audit.TargetTenant, audit.ResultError, map[string]any{
			"reason": "require_db_failed",
			"before": before.Format(time.RFC3339),
		})
		return 0, err
	}

	deleted, err := tda.Audit().Purge(ctx, before)
	if err != nil {
		emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventAuditPurged, tda.ID(), audit.TargetTenant, audit.ResultError, map[string]any{
			"reason": "purge_failed",
			"before": before.Format(time.RFC3339),
		})
		return 0, err
	}

	emitAdminEvent(ctx, s.auditBus, tda.ID(), audit.EventAuditPurged, tda.ID(), audit.TargetTenant, audit.ResultSuccess, map[string]any{
		"before":        before.Format(time.RFC3339),
		"deleted_count": deleted,
	})

	return deleted, nil
}
