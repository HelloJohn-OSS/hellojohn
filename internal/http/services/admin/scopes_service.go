package admin

import (
	"context"
	"fmt"

	"github.com/dropDatabas3/hellojohn/internal/controlplane"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// ScopeService define las operaciones de scopes para el admin API.
type ScopeService interface {
	List(ctx context.Context, tenantSlug string) ([]repository.Scope, error)
	Get(ctx context.Context, tenantSlug, name string) (*repository.Scope, error)
	Upsert(ctx context.Context, tenantSlug string, input repository.ScopeInput) (*repository.Scope, error)
	Delete(ctx context.Context, tenantSlug, name string) error
}

// scopeService implementa ScopeService usando controlplane.Service.
type scopeService struct {
	cp controlplane.Service
}

// NewScopeService crea un nuevo servicio de scopes.
func NewScopeService(cp controlplane.Service) ScopeService {
	return &scopeService{cp: cp}
}

const componentScopes = "admin.scopes"

func (s *scopeService) List(ctx context.Context, tenantSlug string) ([]repository.Scope, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentScopes),
		logger.Op("List"),
		logger.TenantSlug(tenantSlug),
	)

	scopes, err := s.cp.ListScopes(ctx, tenantSlug)
	if err != nil {
		log.Error("failed to list scopes", logger.Err(err))
		return nil, err
	}

	log.Debug("scopes listed", logger.Int("count", len(scopes)))
	return scopes, nil
}

func (s *scopeService) Get(ctx context.Context, tenantSlug, name string) (*repository.Scope, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentScopes),
		logger.Op("Get"),
		logger.TenantSlug(tenantSlug),
		logger.String("scope_name", name),
	)

	if name == "" {
		return nil, fmt.Errorf("scope name is required")
	}

	scopes, err := s.cp.ListScopes(ctx, tenantSlug)
	if err != nil {
		log.Error("failed to list scopes for get", logger.Err(err))
		return nil, err
	}

	for i := range scopes {
		if scopes[i].Name == name {
			return &scopes[i], nil
		}
	}

	log.Debug("scope not found")
	return nil, repository.ErrNotFound
}

func (s *scopeService) Upsert(ctx context.Context, tenantSlug string, input repository.ScopeInput) (*repository.Scope, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentScopes),
		logger.Op("Upsert"),
		logger.TenantSlug(tenantSlug),
		logger.String("scope_name", input.Name),
	)

	if input.Name == "" {
		return nil, fmt.Errorf("scope name is required")
	}

	scope, err := s.cp.UpsertScope(ctx, tenantSlug, input)
	if err != nil {
		log.Error("failed to upsert scope", logger.Err(err))
		return nil, err
	}

	log.Info("scope upserted")
	return scope, nil
}

func (s *scopeService) Delete(ctx context.Context, tenantSlug, name string) error {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentScopes),
		logger.Op("Delete"),
		logger.TenantSlug(tenantSlug),
		logger.String("scope_name", name),
	)

	if name == "" {
		return fmt.Errorf("scope name is required")
	}

	if err := s.cp.DeleteScope(ctx, tenantSlug, name); err != nil {
		log.Error("failed to delete scope", logger.Err(err))
		return err
	}

	log.Info("scope deleted")
	return nil
}
