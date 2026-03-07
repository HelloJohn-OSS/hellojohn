package admin

import (
	"context"
	"fmt"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// TokensAdminService define las operaciones de administración de tokens.
type TokensAdminService interface {
	// List lista tokens con filtros y paginación.
	List(ctx context.Context, tenantID string, filter dto.ListTokensFilter) (*dto.ListTokensResponse, error)

	// Get obtiene un token por su ID.
	Get(ctx context.Context, tenantID, tokenID string) (*dto.TokenResponse, error)

	// Revoke revoca un token individual.
	Revoke(ctx context.Context, tenantID, tokenID string) error

	// RevokeByUser revoca todos los tokens de un usuario.
	RevokeByUser(ctx context.Context, tenantID, userID string) (*dto.RevokeResponse, error)

	// RevokeByClient revoca todos los tokens de un client.
	RevokeByClient(ctx context.Context, tenantID, clientID string) (*dto.RevokeResponse, error)

	// RevokeAll revoca todos los tokens activos del tenant.
	RevokeAll(ctx context.Context, tenantID string) (*dto.RevokeResponse, error)

	// GetStats obtiene estadísticas de tokens.
	GetStats(ctx context.Context, tenantID string) (*dto.TokenStats, error)
}

// TokensAdminDeps contiene las dependencias del servicio.
type TokensAdminDeps struct {
	DAL store.DataAccessLayer
}

type tokensAdminService struct {
	deps TokensAdminDeps
}

// NewTokensAdminService crea una nueva instancia del servicio.
func NewTokensAdminService(deps TokensAdminDeps) TokensAdminService {
	return &tokensAdminService{deps: deps}
}

const componentTokensAdmin = "admin.tokens"

// Errores del servicio
var (
	ErrTokenNotFound     = fmt.Errorf("token not found")
	ErrTokenTenantNoDB   = fmt.Errorf("tenant has no database configured")
	ErrTokenInvalidInput = fmt.Errorf("invalid input")
)

func (s *tokensAdminService) List(ctx context.Context, tenantID string, filter dto.ListTokensFilter) (*dto.ListTokensResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentTokensAdmin),
		logger.Op("List"),
		logger.TenantID(tenantID),
	)

	// 1. Obtener acceso al tenant
	tda, err := s.deps.DAL.ForTenant(ctx, tenantID)
	if err != nil {
		log.Error("failed to get tenant", logger.Err(err))
		return nil, err
	}

	// 2. Verificar que tenant tenga DB
	if err := tda.RequireDB(); err != nil {
		log.Warn("tenant has no database")
		return nil, ErrTokenTenantNoDB
	}

	// 3. Convertir filtro DTO a repository filter
	repoFilter := repository.ListTokensFilter{
		UserID:   filter.UserID,
		ClientID: filter.ClientID,
		Status:   filter.Status,
		Search:   filter.Search,
		Page:     filter.Page,
		PageSize: filter.PageSize,
	}

	// 4. Obtener tokens
	tokens, err := tda.Tokens().List(ctx, repoFilter)
	if err != nil {
		log.Error("failed to list tokens", logger.Err(err))
		return nil, fmt.Errorf("failed to list tokens: %w", err)
	}

	// 5. Obtener conteo total
	totalCount, err := tda.Tokens().Count(ctx, repoFilter)
	if err != nil {
		log.Error("failed to count tokens", logger.Err(err))
		return nil, fmt.Errorf("failed to count tokens: %w", err)
	}

	// 6. Mapear a DTOs
	tokenResponses := make([]dto.TokenResponse, len(tokens))
	for i, token := range tokens {
		tokenResponses[i] = mapTokenToResponse(&token)
	}

	log.Debug("tokens listed", logger.Int("count", len(tokens)), logger.Int("total", totalCount))

	return &dto.ListTokensResponse{
		Tokens:     tokenResponses,
		TotalCount: totalCount,
		Page:       filter.Page,
		PageSize:   filter.PageSize,
	}, nil
}

func (s *tokensAdminService) Get(ctx context.Context, tenantID, tokenID string) (*dto.TokenResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentTokensAdmin),
		logger.Op("Get"),
		logger.TenantID(tenantID),
		logger.String("token_id", tokenID),
	)

	if tokenID == "" {
		return nil, fmt.Errorf("%w: token_id is required", ErrTokenInvalidInput)
	}

	// 1. Obtener acceso al tenant
	tda, err := s.deps.DAL.ForTenant(ctx, tenantID)
	if err != nil {
		log.Error("failed to get tenant", logger.Err(err))
		return nil, err
	}

	// 2. Verificar que tenant tenga DB
	if err := tda.RequireDB(); err != nil {
		log.Warn("tenant has no database")
		return nil, ErrTokenTenantNoDB
	}

	// 3. Obtener token
	token, err := tda.Tokens().GetByID(ctx, tokenID)
	if err != nil {
		if repository.IsNotFound(err) {
			return nil, ErrTokenNotFound
		}
		log.Error("failed to get token", logger.Err(err))
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	response := mapTokenToResponse(token)
	return &response, nil
}

func (s *tokensAdminService) Revoke(ctx context.Context, tenantID, tokenID string) error {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentTokensAdmin),
		logger.Op("Revoke"),
		logger.TenantID(tenantID),
		logger.String("token_id", tokenID),
	)

	if tokenID == "" {
		return fmt.Errorf("%w: token_id is required", ErrTokenInvalidInput)
	}

	// 1. Obtener acceso al tenant
	tda, err := s.deps.DAL.ForTenant(ctx, tenantID)
	if err != nil {
		log.Error("failed to get tenant", logger.Err(err))
		return err
	}

	// 2. Verificar que tenant tenga DB
	if err := tda.RequireDB(); err != nil {
		log.Warn("tenant has no database")
		return ErrTokenTenantNoDB
	}

	// 3. Revocar token
	if err := tda.Tokens().Revoke(ctx, tokenID); err != nil {
		log.Error("failed to revoke token", logger.Err(err))
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	log.Info("token revoked")
	return nil
}

func (s *tokensAdminService) RevokeByUser(ctx context.Context, tenantID, userID string) (*dto.RevokeResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentTokensAdmin),
		logger.Op("RevokeByUser"),
		logger.TenantID(tenantID),
		logger.UserID(userID),
	)

	if userID == "" {
		return nil, fmt.Errorf("%w: user_id is required", ErrTokenInvalidInput)
	}

	// 1. Obtener acceso al tenant
	tda, err := s.deps.DAL.ForTenant(ctx, tenantID)
	if err != nil {
		log.Error("failed to get tenant", logger.Err(err))
		return nil, err
	}

	// 2. Verificar que tenant tenga DB
	if err := tda.RequireDB(); err != nil {
		log.Warn("tenant has no database")
		return nil, ErrTokenTenantNoDB
	}

	// 3. Revocar todos los tokens del usuario (sin filtrar por client)
	revokedCount, err := tda.Tokens().RevokeAllByUser(ctx, userID, "")
	if err != nil {
		log.Error("failed to revoke tokens by user", logger.Err(err))
		return nil, fmt.Errorf("failed to revoke tokens: %w", err)
	}

	log.Info("tokens revoked by user", logger.Int("count", revokedCount))

	return &dto.RevokeResponse{
		RevokedCount: revokedCount,
		Message:      fmt.Sprintf("%d tokens revocados para el usuario", revokedCount),
	}, nil
}

func (s *tokensAdminService) RevokeByClient(ctx context.Context, tenantID, clientID string) (*dto.RevokeResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentTokensAdmin),
		logger.Op("RevokeByClient"),
		logger.TenantID(tenantID),
		logger.String("client_id", clientID),
	)

	if clientID == "" {
		return nil, fmt.Errorf("%w: client_id is required", ErrTokenInvalidInput)
	}

	// 1. Obtener acceso al tenant
	tda, err := s.deps.DAL.ForTenant(ctx, tenantID)
	if err != nil {
		log.Error("failed to get tenant", logger.Err(err))
		return nil, err
	}

	// 2. Verificar que tenant tenga DB
	if err := tda.RequireDB(); err != nil {
		log.Warn("tenant has no database")
		return nil, ErrTokenTenantNoDB
	}

	// 3. Contar tokens antes de revocar
	filter := repository.ListTokensFilter{
		ClientID: &clientID,
		Status:   strPtr("active"),
	}
	countBefore, err := tda.Tokens().Count(ctx, filter)
	if err != nil {
		log.Error("failed to count active tokens before revocation", logger.Err(err))
		return nil, fmt.Errorf("failed to count tokens before revocation: %w", err)
	}

	// 4. Revocar todos los tokens del client
	if err := tda.Tokens().RevokeAllByClient(ctx, clientID); err != nil {
		log.Error("failed to revoke tokens by client", logger.Err(err))
		return nil, fmt.Errorf("failed to revoke tokens: %w", err)
	}

	log.Info("tokens revoked by client", logger.Int("count", countBefore))

	return &dto.RevokeResponse{
		RevokedCount: countBefore,
		Message:      fmt.Sprintf("%d tokens revocados para el client", countBefore),
	}, nil
}

func (s *tokensAdminService) RevokeAll(ctx context.Context, tenantID string) (*dto.RevokeResponse, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentTokensAdmin),
		logger.Op("RevokeAll"),
		logger.TenantID(tenantID),
	)

	// 1. Obtener acceso al tenant
	tda, err := s.deps.DAL.ForTenant(ctx, tenantID)
	if err != nil {
		log.Error("failed to get tenant", logger.Err(err))
		return nil, err
	}

	// 2. Verificar que tenant tenga DB
	if err := tda.RequireDB(); err != nil {
		log.Warn("tenant has no database")
		return nil, ErrTokenTenantNoDB
	}

	// 3. Revocar todos los tokens
	revokedCount, err := tda.Tokens().RevokeAll(ctx)
	if err != nil {
		log.Error("failed to revoke all tokens", logger.Err(err))
		return nil, fmt.Errorf("failed to revoke all tokens: %w", err)
	}

	log.Warn("all tokens revoked", logger.Int("count", revokedCount))

	return &dto.RevokeResponse{
		RevokedCount: revokedCount,
		Message:      fmt.Sprintf("%d tokens revocados en total", revokedCount),
	}, nil
}

func (s *tokensAdminService) GetStats(ctx context.Context, tenantID string) (*dto.TokenStats, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentTokensAdmin),
		logger.Op("GetStats"),
		logger.TenantID(tenantID),
	)

	// 1. Obtener acceso al tenant
	tda, err := s.deps.DAL.ForTenant(ctx, tenantID)
	if err != nil {
		log.Error("failed to get tenant", logger.Err(err))
		return nil, err
	}

	// 2. Verificar que tenant tenga DB
	if err := tda.RequireDB(); err != nil {
		log.Warn("tenant has no database")
		return nil, ErrTokenTenantNoDB
	}

	// 3. Obtener estadísticas
	stats, err := tda.Tokens().GetStats(ctx)
	if err != nil {
		log.Error("failed to get stats", logger.Err(err))
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}

	// 4. Mapear a DTO
	byClient := make([]dto.ClientTokenCount, len(stats.ByClient))
	for i, cc := range stats.ByClient {
		byClient[i] = dto.ClientTokenCount{
			ClientID: cc.ClientID,
			Count:    cc.Count,
		}
	}

	log.Debug("stats retrieved", logger.Int("total_active", stats.TotalActive))

	return &dto.TokenStats{
		TotalActive:      stats.TotalActive,
		IssuedToday:      stats.IssuedToday,
		RevokedToday:     stats.RevokedToday,
		AvgLifetimeHours: stats.AvgLifetimeHours,
		ByClient:         byClient,
	}, nil
}

// ─── Helpers ───

func mapTokenToResponse(token *repository.RefreshToken) dto.TokenResponse {
	status := "active"
	now := time.Now()

	if token.RevokedAt != nil {
		status = "revoked"
	} else if token.ExpiresAt.Before(now) {
		status = "expired"
	}

	return dto.TokenResponse{
		ID:        token.ID,
		UserID:    token.UserID,
		UserEmail: token.UserEmail,
		ClientID:  token.ClientID,
		IssuedAt:  token.IssuedAt,
		ExpiresAt: token.ExpiresAt,
		RevokedAt: token.RevokedAt,
		Status:    status,
	}
}

func strPtr(s string) *string {
	return &s
}
