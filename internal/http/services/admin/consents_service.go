package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	"github.com/google/uuid"
)

// ConsentService define las operaciones de consents para el admin API.
type ConsentService interface {
	Upsert(ctx context.Context, tda store.TenantDataAccess, userID, clientID string, scopes []string) (*repository.Consent, error)
	ListByUser(ctx context.Context, tda store.TenantDataAccess, userID string, activeOnly bool) ([]repository.Consent, error)
	ListAll(ctx context.Context, tda store.TenantDataAccess, page, pageSize int, activeOnly bool) ([]repository.Consent, int, error)
	Get(ctx context.Context, tda store.TenantDataAccess, userID, clientID string) (*repository.Consent, error)
	Revoke(ctx context.Context, tda store.TenantDataAccess, userID, clientID string, at time.Time) error
	ResolveClientUUID(ctx context.Context, tda store.TenantDataAccess, clientIDOrPublic string) (string, error)
}

// consentService implementa ConsentService.
type consentService struct{}

// NewConsentService crea un nuevo service de consents.
func NewConsentService() ConsentService {
	return &consentService{}
}

const (
	componentConsents = "admin.consents"
	errClientIDReq    = "client_id is required"
	errUserIDReq      = "user_id is required"
	errScopesReq      = "scopes are required"
)

func (s *consentService) Upsert(ctx context.Context, tda store.TenantDataAccess, userID, clientID string, scopes []string) (*repository.Consent, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentConsents),
		logger.Op("Upsert"),
		logger.UserID(userID),
		logger.ClientID(clientID),
	)

	if err := tda.RequireDB(); err != nil {
		return nil, err
	}

	if userID == "" {
		return nil, fmt.Errorf(errUserIDReq)
	}
	if clientID == "" {
		return nil, fmt.Errorf(errClientIDReq)
	}
	if len(scopes) == 0 {
		return nil, fmt.Errorf(errScopesReq)
	}

	// Resolver clientID si es público
	resolvedClientID, err := s.ResolveClientUUID(ctx, tda, clientID)
	if err != nil {
		return nil, err
	}

	consent, err := tda.Consents().Upsert(ctx, tda.ID(), userID, resolvedClientID, scopes)
	if err != nil {
		log.Error("upsert failed", logger.Err(err))
		return nil, err
	}

	log.Info("consent upserted")
	return consent, nil
}

func (s *consentService) ListByUser(ctx context.Context, tda store.TenantDataAccess, userID string, activeOnly bool) ([]repository.Consent, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentConsents),
		logger.Op("ListByUser"),
		logger.UserID(userID),
	)

	if err := tda.RequireDB(); err != nil {
		return nil, err
	}

	if userID == "" {
		return nil, fmt.Errorf(errUserIDReq)
	}

	consents, err := tda.Consents().ListByUser(ctx, tda.ID(), userID, activeOnly)
	if err != nil {
		log.Error("list failed", logger.Err(err))
		return nil, err
	}

	log.Debug("consents listed", logger.Int("count", len(consents)))
	return consents, nil
}

func (s *consentService) ListAll(ctx context.Context, tda store.TenantDataAccess, page, pageSize int, activeOnly bool) ([]repository.Consent, int, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentConsents),
		logger.Op("ListAll"),
	)

	if err := tda.RequireDB(); err != nil {
		return nil, 0, err
	}

	// Defaults
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 50
	}

	offset := (page - 1) * pageSize

	consents, total, err := tda.Consents().ListAll(ctx, tda.ID(), pageSize, offset, activeOnly)
	if err != nil {
		log.Error("list all failed", logger.Err(err))
		return nil, 0, err
	}

	log.Debug("all consents listed", logger.Int("count", len(consents)), logger.Int("total", total))
	return consents, total, nil
}

func (s *consentService) Get(ctx context.Context, tda store.TenantDataAccess, userID, clientID string) (*repository.Consent, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentConsents),
		logger.Op("Get"),
		logger.UserID(userID),
		logger.ClientID(clientID),
	)

	if err := tda.RequireDB(); err != nil {
		return nil, err
	}

	// Resolver clientID si es público
	resolvedClientID, err := s.ResolveClientUUID(ctx, tda, clientID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, repository.ErrNotFound
		}
		return nil, err
	}

	consent, err := tda.Consents().Get(ctx, tda.ID(), userID, resolvedClientID)
	if err != nil {
		log.Debug("get failed", logger.Err(err))
		return nil, err
	}

	return consent, nil
}

func (s *consentService) Revoke(ctx context.Context, tda store.TenantDataAccess, userID, clientID string, at time.Time) error {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentConsents),
		logger.Op("Revoke"),
		logger.UserID(userID),
		logger.ClientID(clientID),
	)

	if err := tda.RequireDB(); err != nil {
		return err
	}

	if userID == "" {
		return fmt.Errorf(errUserIDReq)
	}
	if clientID == "" {
		return fmt.Errorf(errClientIDReq)
	}

	// Resolver clientID si es público
	resolvedClientID, err := s.ResolveClientUUID(ctx, tda, clientID)
	if err != nil {
		return err
	}

	// Revocar consent
	if err := tda.Consents().Revoke(ctx, tda.ID(), userID, resolvedClientID); err != nil {
		log.Error("revoke failed", logger.Err(err))
		return err
	}

	// Best-effort: revocar refresh tokens del usuario para este cliente
	if tokens := tda.Tokens(); tokens != nil {
		if _, err := tokens.RevokeAllByUser(ctx, userID, resolvedClientID); err != nil {
			log.Warn("best-effort token revocation failed", logger.Err(err))
			// No retornamos error - es best-effort
		}
	}

	log.Info("consent revoked")
	return nil
}

func (s *consentService) ResolveClientUUID(ctx context.Context, tda store.TenantDataAccess, clientIDOrPublic string) (string, error) {
	if clientIDOrPublic == "" {
		return "", fmt.Errorf(errClientIDReq)
	}

	// Si es UUID válido, usarlo directo
	if _, err := uuid.Parse(clientIDOrPublic); err == nil {
		return clientIDOrPublic, nil
	}

	// Es client_id público, resolver via Clients repo
	clients := tda.Clients()
	if clients == nil {
		return "", fmt.Errorf("client lookup not available")
	}

	client, err := clients.Get(ctx, clientIDOrPublic)
	if err != nil {
		return "", err
	}

	return client.ID, nil
}
