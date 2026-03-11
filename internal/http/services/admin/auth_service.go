// Package admin provides services for administrative HTTP operations.
package admin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	controlplane "github.com/dropDatabas3/hellojohn/internal/controlplane"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	"github.com/dropDatabas3/hellojohn/internal/jwt"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// AuthService defines authentication operations for admins.
type AuthService interface {
	Login(ctx context.Context, req dto.AdminLoginRequest) (*dto.AdminLoginResult, error)
	Refresh(ctx context.Context, req dto.AdminRefreshRequest) (*dto.AdminLoginResult, error)
}

// authService implements AuthService.
type authService struct {
	cp         controlplane.Service
	issuer     *jwt.Issuer
	refreshTTL time.Duration
	auditBus   *audit.AuditBus
}

// AuthServiceDeps contains dependencies for admin authentication service.
type AuthServiceDeps struct {
	ControlPlane controlplane.Service
	Issuer       *jwt.Issuer
	RefreshTTL   time.Duration
	AuditBus     *audit.AuditBus
}

// NewAuthService creates a new admin authentication service.
func NewAuthService(deps AuthServiceDeps) AuthService {
	if deps.RefreshTTL == 0 {
		deps.RefreshTTL = 30 * 24 * time.Hour
	}
	return &authService{
		cp:         deps.ControlPlane,
		issuer:     deps.Issuer,
		refreshTTL: deps.RefreshTTL,
		auditBus:   deps.AuditBus,
	}
}

// Service errors.
var (
	ErrInvalidAdminCredentials = fmt.Errorf("invalid admin credentials")
	ErrAdminDisabled           = fmt.Errorf("admin account disabled")
	ErrAdminNotVerified        = fmt.Errorf("admin email not verified")
	ErrInvalidRefreshToken     = fmt.Errorf("invalid refresh token")
	ErrRefreshTokenExpired     = fmt.Errorf("refresh token expired")
)

// Login authenticates an admin with email and password.
func (s *authService) Login(ctx context.Context, req dto.AdminLoginRequest) (*dto.AdminLoginResult, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("admin.auth"),
		logger.Op("Login"),
	)

	admin, err := s.cp.GetAdminByEmail(ctx, req.Email)
	if err != nil {
		if repository.IsNotFound(err) || errors.Is(err, controlplane.ErrAdminNotFound) {
			s.emitAuthEvent(ctx, audit.EventLoginFailed, audit.ResultFailure, "", "", map[string]any{
				"method": "admin_password",
				"reason": "invalid_credentials",
			})
			log.Warn("admin not found")
			return nil, ErrInvalidAdminCredentials
		}
		s.emitAuthEvent(ctx, audit.EventLoginFailed, audit.ResultError, "", "", map[string]any{
			"method": "admin_password",
			"reason": "admin_lookup_failed",
		})
		log.Error("failed to get admin", logger.Err(err))
		return nil, err
	}

	if !s.cp.CheckAdminPassword(admin.PasswordHash, req.Password) {
		s.emitAuthEvent(ctx, audit.EventLoginFailed, audit.ResultFailure, admin.ID, string(admin.Type), map[string]any{
			"method": "admin_password",
			"reason": "invalid_credentials",
		})
		log.Warn("invalid password")
		return nil, ErrInvalidAdminCredentials
	}

	if admin.DisabledAt != nil {
		s.emitAuthEvent(ctx, audit.EventLoginFailed, audit.ResultFailure, admin.ID, string(admin.Type), map[string]any{
			"method": "admin_password",
			"reason": "admin_disabled",
		})
		log.Warn("admin disabled")
		return nil, ErrAdminDisabled
	}

	// Reject pending (invite not yet accepted)
	if admin.Status == "pending" {
		s.emitAuthEvent(ctx, audit.EventLoginFailed, audit.ResultFailure, admin.ID, string(admin.Type), map[string]any{
			"method": "admin_password",
			"reason": "admin_pending_invite",
		})
		log.Warn("admin has not accepted invite yet")
		return nil, ErrAdminDisabled
	}

	accessToken, expiresIn, err := s.issuer.IssueAdminAccess(ctx, jwt.AdminAccessClaims{
		AdminID:   admin.ID,
		Email:     admin.Email,
		AdminType: string(admin.Type),
		Tenants:   buildTenantClaims(admin.TenantAccess),
		Perms:     jwt.DefaultAdminPerms(string(admin.Type)),
	})
	if err != nil {
		s.emitAuthEvent(ctx, audit.EventLoginFailed, audit.ResultError, admin.ID, string(admin.Type), map[string]any{
			"method": "admin_password",
			"reason": "token_issuance_failed",
		})
		log.Error("failed to issue access token", logger.Err(err))
		return nil, fmt.Errorf("failed to issue access token: %w", err)
	}

	refreshToken, err := generateOpaqueToken()
	if err != nil {
		s.emitAuthEvent(ctx, audit.EventLoginFailed, audit.ResultError, admin.ID, string(admin.Type), map[string]any{
			"method": "admin_password",
			"reason": "refresh_token_generation_failed",
		})
		log.Error("failed to generate refresh token", logger.Err(err))
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	err = s.cp.CreateAdminRefreshToken(ctx, controlplane.AdminRefreshTokenInput{
		AdminID:   admin.ID,
		TokenHash: hashToken(refreshToken),
		ExpiresAt: time.Now().Add(s.refreshTTL),
	})
	if err != nil {
		s.emitAuthEvent(ctx, audit.EventLoginFailed, audit.ResultError, admin.ID, string(admin.Type), map[string]any{
			"method": "admin_password",
			"reason": "refresh_token_persist_failed",
		})
		log.Error("failed to create refresh token", logger.Err(err))
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	s.emitAuthEvent(ctx, audit.EventLogin, audit.ResultSuccess, admin.ID, string(admin.Type), map[string]any{
		"method": "admin_password",
	})

	log.Debug("refresh token persisted")
	log.Info("admin logged in successfully")

	return &dto.AdminLoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    expiresIn,
		TokenType:    "Bearer",
		Admin: dto.AdminInfo{
			ID:      admin.ID,
			Email:   admin.Email,
			Type:    string(admin.Type),
			Tenants: admin.AssignedTenants,
		},
	}, nil
}

// Refresh renews the admin access token using a valid refresh token.
func (s *authService) Refresh(ctx context.Context, req dto.AdminRefreshRequest) (*dto.AdminLoginResult, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("admin.auth"),
		logger.Op("Refresh"),
	)

	tokenHash := hashToken(req.RefreshToken)
	adminRefresh, err := s.cp.GetAdminRefreshToken(ctx, tokenHash)
	if err != nil {
		if repository.IsNotFound(err) || errors.Is(err, controlplane.ErrRefreshTokenNotFound) {
			s.emitAuthEvent(ctx, audit.EventTokenRefreshed, audit.ResultFailure, "", "", map[string]any{
				"method": "admin_refresh",
				"reason": "invalid_refresh_token",
			})
			log.Warn("refresh token not found")
			return nil, ErrInvalidRefreshToken
		}
		s.emitAuthEvent(ctx, audit.EventTokenRefreshed, audit.ResultError, "", "", map[string]any{
			"method": "admin_refresh",
			"reason": "refresh_token_lookup_failed",
		})
		log.Error("failed to get refresh token", logger.Err(err))
		return nil, err
	}

	if time.Now().After(adminRefresh.ExpiresAt) {
		s.emitAuthEvent(ctx, audit.EventTokenRefreshed, audit.ResultFailure, adminRefresh.AdminID, "", map[string]any{
			"method": "admin_refresh",
			"reason": "refresh_token_expired",
		})
		log.Warn("refresh token expired")
		return nil, ErrRefreshTokenExpired
	}

	admin, err := s.cp.GetAdmin(ctx, adminRefresh.AdminID)
	if err != nil {
		if repository.IsNotFound(err) || errors.Is(err, controlplane.ErrAdminNotFound) {
			s.emitAuthEvent(ctx, audit.EventTokenRefreshed, audit.ResultFailure, adminRefresh.AdminID, "", map[string]any{
				"method": "admin_refresh",
				"reason": "admin_not_found",
			})
			log.Warn("admin not found for refresh token")
			return nil, ErrInvalidRefreshToken
		}
		s.emitAuthEvent(ctx, audit.EventTokenRefreshed, audit.ResultError, adminRefresh.AdminID, "", map[string]any{
			"method": "admin_refresh",
			"reason": "admin_lookup_failed",
		})
		log.Error("failed to get admin", logger.Err(err))
		return nil, err
	}

	if admin.DisabledAt != nil {
		s.emitAuthEvent(ctx, audit.EventTokenRefreshed, audit.ResultFailure, admin.ID, string(admin.Type), map[string]any{
			"method": "admin_refresh",
			"reason": "admin_disabled",
		})
		log.Warn("admin disabled")
		return nil, ErrAdminDisabled
	}

	accessToken, expiresIn, err := s.issuer.IssueAdminAccess(ctx, jwt.AdminAccessClaims{
		AdminID:   admin.ID,
		Email:     admin.Email,
		AdminType: string(admin.Type),
		Tenants:   buildTenantClaims(admin.TenantAccess),
		Perms:     jwt.DefaultAdminPerms(string(admin.Type)),
	})
	if err != nil {
		s.emitAuthEvent(ctx, audit.EventTokenRefreshed, audit.ResultError, admin.ID, string(admin.Type), map[string]any{
			"method": "admin_refresh",
			"reason": "token_issuance_failed",
		})
		log.Error("failed to issue access token", logger.Err(err))
		return nil, fmt.Errorf("failed to issue access token: %w", err)
	}

	s.emitAuthEvent(ctx, audit.EventTokenRefreshed, audit.ResultSuccess, admin.ID, string(admin.Type), map[string]any{
		"method": "admin_refresh",
	})

	log.Info("admin token refreshed successfully")

	return &dto.AdminLoginResult{
		AccessToken:  accessToken,
		RefreshToken: req.RefreshToken,
		ExpiresIn:    expiresIn,
		TokenType:    "Bearer",
		Admin: dto.AdminInfo{
			ID:      admin.ID,
			Email:   admin.Email,
			Type:    string(admin.Type),
			Tenants: admin.AssignedTenants,
		},
	}, nil
}

var opaqueTokenReader io.Reader = rand.Reader

// generateOpaqueToken generates a random opaque token.
func generateOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(opaqueTokenReader, b); err != nil {
		return "", fmt.Errorf("generate opaque token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (s *authService) emitAuthEvent(ctx context.Context, eventType audit.EventType, result, adminID, adminType string, meta map[string]any) {
	if s.auditBus == nil {
		return
	}

	evt := audit.NewEvent(eventType, audit.ControlPlaneTenantID).
		WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx))

	if strings.TrimSpace(result) != "" {
		evt = evt.WithResult(result)
	}

	if strings.TrimSpace(adminID) != "" {
		evt = evt.WithActor(adminID, audit.ActorAdmin).
			WithTarget(adminID, audit.TargetUser)
	} else {
		evt = evt.WithActor("", audit.ActorSystem)
	}

	if strings.TrimSpace(adminType) != "" {
		evt = evt.WithMeta("admin_type", adminType)
	}

	for k, v := range meta {
		evt = evt.WithMeta(k, v)
	}

	s.auditBus.Emit(evt)
}

// Note: hashToken() already exists in users_service.go (SHA-256) and is reused.

// buildTenantClaims convierte []repository.TenantAccessEntry a []jwt.TenantAccessClaim
// para incluir en el AdminAccessClaims del JWT.
func buildTenantClaims(entries []repository.TenantAccessEntry) []jwt.TenantAccessClaim {
	if len(entries) == 0 {
		return nil
	}
	out := make([]jwt.TenantAccessClaim, 0, len(entries))
	for _, e := range entries {
		role := e.Role
		if role == "" {
			role = "member" // default seguro
		}
		out = append(out, jwt.TenantAccessClaim{Slug: e.TenantSlug, Role: role})
	}
	return out
}
