package auth

import (
	"context"
	"fmt"
	"net"
	neturl "net/url"
	"strings"

	cache "github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// LogoutService defines operations for logout.
type LogoutService interface {
	// Logout revokes refresh token and/or session in a single request.
	Logout(ctx context.Context, in dto.LogoutRequest, tenantSlug string) (*dto.LogoutResult, error)
	// LogoutAll revokes all refresh tokens for a user.
	LogoutAll(ctx context.Context, in dto.LogoutAllRequest, tenantSlug string) error
}

// LogoutDeps contains dependencies for the logout service.
type LogoutDeps struct {
	DAL          store.DataAccessLayer
	SessionCache cache.Client
}

type logoutService struct {
	deps LogoutDeps
}

// NewLogoutService creates a new logout service.
func NewLogoutService(deps LogoutDeps) LogoutService {
	return &logoutService{deps: deps}
}

// Logout errors
var (
	ErrLogoutMissingFields = fmt.Errorf("missing required fields")
	ErrLogoutInvalidClient = fmt.Errorf("invalid client")
	ErrLogoutNoDatabase    = fmt.Errorf("no database for tenant")
	ErrLogoutNotSupported  = fmt.Errorf("mass revocation not supported")
	ErrLogoutFailed        = fmt.Errorf("revocation failed")
)

// Logout revokes refresh token and/or session in one call (idempotent).
func (s *logoutService) Logout(ctx context.Context, in dto.LogoutRequest, tenantSlug string) (*dto.LogoutResult, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("auth.logout"),
		logger.Op("Logout"),
	)

	// Normalize
	in.RefreshToken = strings.TrimSpace(in.RefreshToken)
	in.ClientID = strings.TrimSpace(in.ClientID)
	in.TenantID = strings.TrimSpace(in.TenantID)
	in.SessionID = strings.TrimSpace(in.SessionID)
	in.PostLogoutRedirectURI = strings.TrimSpace(in.PostLogoutRedirectURI)

	result := &dto.LogoutResult{}

	// Resolve effective tenant from context/header/query first, then request body.
	effectiveTenant := strings.TrimSpace(tenantSlug)
	if effectiveTenant == "" {
		effectiveTenant = in.TenantID
	}

	// TODO(GDP-M1): These operations should be wrapped in a transaction to prevent race conditions.
	// Currently uses pool connections which don't guarantee atomicity across calls.
	var tda store.TenantDataAccess
	if in.RefreshToken != "" {
		if in.ClientID == "" || effectiveTenant == "" {
			return nil, ErrLogoutMissingFields
		}
		var err error
		tda, err = s.revokeRefreshToken(ctx, in, effectiveTenant)
		if err != nil {
			return nil, err
		}
	}

	if in.SessionID != "" {
		s.deleteSession(ctx, in.SessionID)
	}

	if in.PostLogoutRedirectURI != "" && in.ClientID != "" {
		// Reuse tenant resolved via refresh flow if available; fallback to effective tenant.
		if tda == nil && effectiveTenant != "" {
			tdaResolved, err := s.deps.DAL.ForTenant(ctx, effectiveTenant)
			if err == nil {
				tda = tdaResolved
			}
		}
		if tda != nil && s.isPostLogoutRedirectAllowed(ctx, tda, in.ClientID, in.PostLogoutRedirectURI) {
			result.PostLogoutRedirectURI = in.PostLogoutRedirectURI
		}
	}

	log.Info("logout successful")
	return result, nil
}

func (s *logoutService) deleteSession(ctx context.Context, sessionID string) {
	if s.deps.SessionCache == nil || sessionID == "" {
		return
	}
	key := "sid:" + tokens.SHA256Base64URL(sessionID)
	if err := s.deps.SessionCache.Delete(ctx, key); err != nil {
		logger.From(ctx).With(
			logger.Layer("service"),
			logger.Component("auth.logout"),
		).Warn("failed to delete session from cache", logger.Err(err))
	}
}

// revokeRefreshToken revokes the full refresh family (idempotent) and returns resolved tenant DA.
func (s *logoutService) revokeRefreshToken(ctx context.Context, in dto.LogoutRequest, tenantSlug string) (store.TenantDataAccess, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("auth.logout"),
		logger.Op("revokeRefreshToken"),
	)

	hash := tokens.SHA256Base64URL(in.RefreshToken)
	tda, err := s.deps.DAL.ForTenant(ctx, tenantSlug)
	if err != nil {
		log.Debug("tenant resolution failed", logger.Err(err))
		return nil, ErrLogoutInvalidClient
	}

	if err := tda.RequireDB(); err != nil {
		log.Debug("tenant DB not available", logger.Err(err))
		return nil, ErrLogoutNoDatabase
	}

	rt, err := tda.Tokens().GetByHash(ctx, hash)
	if err != nil || rt == nil {
		// Idempotent: if not found, consider it already revoked.
		log.Debug("refresh token not found, treating as already revoked")
		return tda, nil
	}

	if !strings.EqualFold(in.ClientID, rt.ClientID) {
		log.Debug("client_id mismatch")
		return nil, ErrLogoutInvalidClient
	}

	// Re-open TDA if token belongs to different tenant.
	if rt.TenantID != "" && !strings.EqualFold(rt.TenantID, tda.ID()) {
		tda2, err := s.deps.DAL.ForTenant(ctx, rt.TenantID)
		if err != nil {
			return nil, ErrLogoutNoDatabase
		}
		if err := tda2.RequireDB(); err != nil {
			return nil, ErrLogoutNoDatabase
		}
		tda = tda2
	}

	rootID, err := tda.Tokens().GetFamilyRoot(ctx, rt.ID)
	if err != nil || strings.TrimSpace(rootID) == "" {
		log.Warn("failed to resolve refresh token family root, fallback to single token revoke", logger.Err(err))
		if err := tda.Tokens().Revoke(ctx, rt.ID); err != nil {
			log.Warn("failed to revoke refresh token", logger.Err(err))
		}
		return tda, nil
	}

	if err := tda.Tokens().RevokeFamily(ctx, rootID); err != nil {
		log.Warn("failed to revoke refresh token family, fallback to single token revoke", logger.Err(err))
		if err := tda.Tokens().Revoke(ctx, rt.ID); err != nil {
			log.Warn("failed to revoke refresh token", logger.Err(err))
		}
		return tda, nil
	}

	return tda, nil
}

func (s *logoutService) isPostLogoutRedirectAllowed(ctx context.Context, tda store.TenantDataAccess, clientID, redirectURI string) bool {
	if tda == nil || clientID == "" || redirectURI == "" {
		return false
	}

	normalizedReq, ok := normalizePostLogoutRedirectURI(redirectURI)
	if !ok {
		return false
	}

	client, err := s.getClientForLogout(ctx, tda, clientID)
	if err != nil || client == nil {
		return false
	}

	for _, allowed := range client.PostLogoutURIs {
		normalizedAllowed, ok := normalizePostLogoutRedirectURI(allowed)
		if ok && normalizedAllowed == normalizedReq {
			return true
		}
	}

	return false
}

func (s *logoutService) getClientForLogout(ctx context.Context, tda store.TenantDataAccess, clientID string) (*repository.Client, error) {
	clientsRepo := tda.Clients()
	if clientsRepo == nil {
		return nil, fmt.Errorf("client repository unavailable")
	}

	// El wrapper de ClientRepository ya tiene el tenantSlug pre-bound.
	return clientsRepo.Get(ctx, clientID)
}

func normalizePostLogoutRedirectURI(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}

	u, err := neturl.Parse(raw)
	if err != nil || u == nil {
		return "", false
	}
	if u.User != nil || strings.TrimSpace(u.Fragment) != "" {
		return "", false
	}

	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme != "https" && scheme != "http" {
		return "", false
	}

	host := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if host == "" {
		return "", false
	}

	port := strings.TrimSpace(u.Port())
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}

	u.Scheme = scheme
	u.Host = formatURLHost(host, port)

	if strings.TrimSpace(u.Path) == "" {
		u.Path = "/"
	}
	if !strings.HasPrefix(u.Path, "/") {
		u.Path = "/" + u.Path
	}

	u.Fragment = ""
	u.User = nil

	return u.String(), true
}

func formatURLHost(host, port string) string {
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

// LogoutAll revokes all refresh tokens for a user.
func (s *logoutService) LogoutAll(ctx context.Context, in dto.LogoutAllRequest, tenantSlug string) error {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("auth.logout"),
		logger.Op("LogoutAll"),
	)

	// Normalize
	in.UserID = strings.TrimSpace(in.UserID)
	in.ClientID = strings.TrimSpace(in.ClientID)

	if in.UserID == "" {
		return ErrLogoutMissingFields
	}

	if tenantSlug == "" {
		return ErrLogoutMissingFields
	}

	// Get TDA for tenant
	tda, err := s.deps.DAL.ForTenant(ctx, tenantSlug)
	if err != nil {
		log.Debug("tenant resolution failed", logger.Err(err))
		return ErrLogoutInvalidClient
	}

	if err := tda.RequireDB(); err != nil {
		log.Debug("tenant DB not available", logger.Err(err))
		return ErrLogoutNoDatabase
	}

	log = log.With(logger.TenantSlug(tda.Slug()), logger.UserID(in.UserID))

	// Revoke all tokens for user (optionally filtered by client)
	count, err := tda.Tokens().RevokeAllByUser(ctx, in.UserID, in.ClientID)
	if err != nil {
		log.Error("mass revocation failed", logger.Err(err))
		return ErrLogoutFailed
	}

	log.Info("logout-all successful", logger.Int("revoked_count", int(count)))
	return nil
}
