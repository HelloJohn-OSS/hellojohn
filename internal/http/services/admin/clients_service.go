// Package admin provee servicios para operaciones administrativas HTTP V2.
package admin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/controlplane"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// ClientService define las operaciones de clients para el admin API.
type ClientService interface {
	List(ctx context.Context, tenantSlug string) ([]repository.Client, error)
	Get(ctx context.Context, tenantSlug, clientID string) (*repository.Client, error)
	Create(ctx context.Context, tenantSlug string, input controlplane.ClientInput) (*repository.Client, error)
	Update(ctx context.Context, tenantSlug string, input controlplane.ClientInput) (*repository.Client, error)
	Delete(ctx context.Context, tenantSlug, clientID string) error
	RevokeSecret(ctx context.Context, tenantSlug, clientID string) (string, error)
}

// clientService implementa ClientService usando controlplane.Service.
type clientService struct {
	dal      store.DataAccessLayer
	cp       controlplane.Service
	auditBus *audit.AuditBus
}

// NewClientService crea un nuevo servicio de clients.
func NewClientService(dal store.DataAccessLayer, cp controlplane.Service, auditBus *audit.AuditBus) ClientService {
	return &clientService{dal: dal, cp: cp, auditBus: auditBus}
}

func (s *clientService) List(ctx context.Context, tenantSlug string) ([]repository.Client, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("admin.clients"),
		logger.Op("List"),
		logger.TenantSlug(tenantSlug),
	)

	clients, err := s.cp.ListClients(ctx, tenantSlug)
	if err != nil {
		log.Error("failed to list clients", logger.Err(err))
		return nil, err
	}

	log.Debug("clients listed", logger.Int("count", len(clients)))
	return clients, nil
}

func (s *clientService) Get(ctx context.Context, tenantSlug, clientID string) (*repository.Client, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("admin.clients"),
		logger.Op("Get"),
		logger.TenantSlug(tenantSlug),
		logger.ClientID(clientID),
	)

	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}

	client, err := s.cp.GetClient(ctx, tenantSlug, clientID)
	if err != nil {
		log.Error("failed to get client", logger.Err(err))
		return nil, err
	}

	log.Debug("client retrieved", logger.ClientID(client.ClientID))
	return client, nil
}

func (s *clientService) Create(ctx context.Context, tenantSlug string, input controlplane.ClientInput) (*repository.Client, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("admin.clients"),
		logger.Op("Create"),
		logger.TenantSlug(tenantSlug),
		logger.ClientID(input.ClientID),
	)

	if input.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}

	client, err := s.cp.CreateClient(ctx, tenantSlug, input)
	if err != nil {
		emitAdminEventWithCanonicalTenantRef(ctx, s.auditBus, s.dal, tenantSlug, audit.EventClientCreated, input.ClientID, audit.TargetClient, audit.ResultError, map[string]any{
			"reason":    "create_client_failed",
			"client_id": input.ClientID,
		})
		log.Error("failed to create client", logger.Err(err))
		return nil, err
	}

	emitAdminEventWithCanonicalTenantRef(ctx, s.auditBus, s.dal, tenantSlug, audit.EventClientCreated, client.ClientID, audit.TargetClient, audit.ResultSuccess, map[string]any{
		"client_id": client.ClientID,
	})

	log.Info("client created", logger.ClientID(client.ClientID))
	return client, nil
}

func (s *clientService) Update(ctx context.Context, tenantSlug string, input controlplane.ClientInput) (*repository.Client, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("admin.clients"),
		logger.Op("Update"),
		logger.TenantSlug(tenantSlug),
		logger.ClientID(input.ClientID),
	)

	if input.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}

	client, err := s.cp.UpdateClient(ctx, tenantSlug, input)
	if err != nil {
		emitAdminEventWithCanonicalTenantRef(ctx, s.auditBus, s.dal, tenantSlug, audit.EventClientUpdated, input.ClientID, audit.TargetClient, audit.ResultError, map[string]any{
			"reason":    "update_client_failed",
			"client_id": input.ClientID,
		})
		log.Error("failed to update client", logger.Err(err))
		return nil, err
	}

	emitAdminEventWithCanonicalTenantRef(ctx, s.auditBus, s.dal, tenantSlug, audit.EventClientUpdated, client.ClientID, audit.TargetClient, audit.ResultSuccess, map[string]any{
		"client_id": client.ClientID,
	})

	log.Info("client updated", logger.ClientID(client.ClientID))
	return client, nil
}

func (s *clientService) Delete(ctx context.Context, tenantSlug, clientID string) error {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("admin.clients"),
		logger.Op("Delete"),
		logger.TenantSlug(tenantSlug),
		logger.ClientID(clientID),
	)

	if clientID == "" {
		return fmt.Errorf("client_id is required")
	}

	if err := s.cp.DeleteClient(ctx, tenantSlug, clientID); err != nil {
		emitAdminEventWithCanonicalTenantRef(ctx, s.auditBus, s.dal, tenantSlug, audit.EventClientDeleted, clientID, audit.TargetClient, audit.ResultError, map[string]any{
			"reason":    "delete_client_failed",
			"client_id": clientID,
		})
		log.Error("failed to delete client", logger.Err(err))
		return err
	}

	emitAdminEventWithCanonicalTenantRef(ctx, s.auditBus, s.dal, tenantSlug, audit.EventClientDeleted, clientID, audit.TargetClient, audit.ResultSuccess, map[string]any{
		"client_id": clientID,
	})

	log.Info("client deleted", logger.ClientID(clientID))
	return nil
}

func (s *clientService) RevokeSecret(ctx context.Context, tenantSlug, clientID string) (string, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("admin.clients"),
		logger.Op("RevokeSecret"),
		logger.TenantSlug(tenantSlug),
		logger.ClientID(clientID),
	)

	if clientID == "" {
		return "", fmt.Errorf("client_id is required")
	}

	// 1. Get existing client
	client, err := s.cp.GetClient(ctx, tenantSlug, clientID)
	if err != nil {
		log.Error("failed to get client", logger.Err(err))
		return "", err
	}

	// 2. Verify client is confidential (only confidential clients have secrets)
	if client.Type != "confidential" {
		log.Warn("attempt to revoke secret for non-confidential client")
		return "", fmt.Errorf("cannot revoke secret for public client")
	}

	// 3. Generate new secret (plaintext)
	newSecret, err := generateClientSecret()
	if err != nil {
		log.Error("failed to generate secret", logger.Err(err))
		return "", fmt.Errorf("failed to generate secret: %w", err)
	}

	// 4. Update client with new secret (controlplane will encrypt it)
	input := controlplane.ClientInput{
		ClientID:                 client.ClientID,
		Name:                     client.Name,
		Type:                     client.Type,
		AuthProfile:              client.AuthProfile,
		Secret:                   newSecret, // Plaintext - controlplane will encrypt
		RedirectURIs:             client.RedirectURIs,
		AllowedOrigins:           client.AllowedOrigins,
		Scopes:                   client.Scopes,
		Providers:                client.Providers,
		RequireEmailVerification: client.RequireEmailVerification,
		ResetPasswordURL:         client.ResetPasswordURL,
		VerifyEmailURL:           client.VerifyEmailURL,
		ClaimSchema:              client.ClaimSchema,
		ClaimMapping:             client.ClaimMapping,
		GrantTypes:               client.GrantTypes,
		AccessTokenTTL:           client.AccessTokenTTL,
		RefreshTokenTTL:          client.RefreshTokenTTL,
		IDTokenTTL:               client.IDTokenTTL,
		PostLogoutURIs:           client.PostLogoutURIs,
		Description:              client.Description,
	}

	if _, err := s.cp.UpdateClient(ctx, tenantSlug, input); err != nil {
		emitAdminEventWithCanonicalTenantRef(ctx, s.auditBus, s.dal, tenantSlug, audit.EventClientUpdated, clientID, audit.TargetClient, audit.ResultError, map[string]any{
			"reason":    "rotate_secret_failed",
			"client_id": clientID,
		})
		log.Error("failed to update client with new secret", logger.Err(err))
		return "", fmt.Errorf("failed to update client: %w", err)
	}

	emitAdminEventWithCanonicalTenantRef(ctx, s.auditBus, s.dal, tenantSlug, audit.EventClientUpdated, clientID, audit.TargetClient, audit.ResultSuccess, map[string]any{
		"method":    "rotate_secret",
		"client_id": clientID,
	})

	log.Info("client secret rotated successfully", logger.ClientID(clientID))
	return newSecret, nil
}

// generateClientSecret generates a cryptographically secure random secret.
func generateClientSecret() (string, error) {
	// Generate 32 random bytes
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// Encode as base64 URL-safe (easier to handle than raw hex)
	return base64.RawURLEncoding.EncodeToString(b), nil
}
