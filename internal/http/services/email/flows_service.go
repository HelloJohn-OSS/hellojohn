package email

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	controlplane "github.com/dropDatabas3/hellojohn/internal/controlplane"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	emailv2 "github.com/dropDatabas3/hellojohn/internal/email"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/email"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"github.com/dropDatabas3/hellojohn/internal/passwordpolicy"
	"github.com/dropDatabas3/hellojohn/internal/security/password"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// FlowsService defines operations for email verification and password reset flows.
type FlowsService interface {
	VerifyEmailStart(ctx context.Context, tda store.TenantDataAccess, req dto.VerifyEmailStartRequest, userID *string) error
	VerifyEmailConfirm(ctx context.Context, tda store.TenantDataAccess, req dto.VerifyEmailConfirmRequest) (*dto.VerifyEmailResult, error)
	ForgotPassword(ctx context.Context, tda store.TenantDataAccess, req dto.ForgotPasswordRequest) error
	ResetPassword(ctx context.Context, tda store.TenantDataAccess, req dto.ResetPasswordRequest) (*dto.ResetPasswordResult, error)
}

// TokenIssuer interface for issuing tokens (auto-login support)
type TokenIssuer interface {
	Issue(ctx context.Context, tenantID, clientID, userID string) (access, refresh string, expiresIn int, err error)
}

// FlowsDeps contains dependencies for the email flows service.
type FlowsDeps struct {
	Email          emailv2.Service
	ControlPlane   controlplane.Service
	VerifyTTL      time.Duration
	ResetTTL       time.Duration
	AutoLoginReset bool
	Issuer         TokenIssuer
}

type flowsService struct {
	email     emailv2.Service
	cp        controlplane.Service
	verifyTTL time.Duration
	resetTTL  time.Duration
	autoLogin bool
	issuer    TokenIssuer
}

// NewFlowsService creates a new FlowsService.
func NewFlowsService(deps FlowsDeps) FlowsService {
	// Defaults
	if deps.VerifyTTL <= 0 {
		deps.VerifyTTL = 48 * time.Hour
	}
	if deps.ResetTTL <= 0 {
		deps.ResetTTL = 1 * time.Hour
	}

	return &flowsService{
		email:     deps.Email,
		cp:        deps.ControlPlane,
		verifyTTL: deps.VerifyTTL,
		resetTTL:  deps.ResetTTL,
		autoLogin: deps.AutoLoginReset,
		issuer:    deps.Issuer,
	}
}

// Service errors
var (
	ErrFlowsMissingTenant   = fmt.Errorf("tenant_id is required")
	ErrFlowsMissingClient   = fmt.Errorf("client_id is required")
	ErrFlowsMissingEmail    = fmt.Errorf("email is required")
	ErrFlowsMissingToken    = fmt.Errorf("token is required")
	ErrFlowsMissingPassword = fmt.Errorf("new_password is required")
	ErrFlowsInvalidToken    = fmt.Errorf("token invalid or expired")
	ErrFlowsUserNotFound    = fmt.Errorf("user not found")
	ErrFlowsNoDatabase      = fmt.Errorf("database not available")
	ErrFlowsWeakPassword    = fmt.Errorf("password does not meet policy")
	ErrFlowsSendFailed      = fmt.Errorf("failed to send email")
	ErrFlowsTenantMismatch  = fmt.Errorf("tenant_id does not match resolved tenant")
)

// Crypto Helpers

func newRawToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// url-safe
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// Actions

func (s *flowsService) VerifyEmailStart(ctx context.Context, tda store.TenantDataAccess, req dto.VerifyEmailStartRequest, userID *string) error {
	log := logger.From(ctx).With(logger.Op("VerifyEmailStart"))

	// req.TenantID check skipped (uses tda)

	if req.ClientID == "" {
		return ErrFlowsMissingClient
	}

	if err := tda.RequireDB(); err != nil {
		return ErrFlowsNoDatabase
	}

	// Tenant Consistency
	tenantID := tda.ID()
	tenantSlug := tda.Slug()
	if tenantSlug == "" {
		tenantSlug = tenantID
	}
	if req.TenantID != "" && req.TenantID != tenantID && req.TenantID != tenantSlug {
		return ErrFlowsTenantMismatch
	}

	users := tda.Users()
	tokens := tda.EmailTokens()
	if tokens == nil {
		log.Error("email tokens repo not wired")
		return fmt.Errorf("email tokens repo not wired")
	}

	// 1) resolver user
	var uid string
	var emailStr string

	if userID != nil && *userID != "" {
		// Authenticated
		u, err := users.GetByID(ctx, *userID)
		if err != nil {
			return ErrFlowsUserNotFound
		}
		uid = u.ID
		emailStr = u.Email
	} else {
		// Unauthenticated
		if strings.TrimSpace(req.Email) == "" {
			return ErrFlowsMissingEmail
		}
		emailStr = strings.ToLower(strings.TrimSpace(req.Email))

		u, _, err := users.GetByEmail(ctx, tenantID, emailStr)
		if err != nil {
			// anti-enum: silent success
			log.Debug("user lookup failed (anti-enum)", logger.Err(err))
			return nil
		}
		uid = u.ID
	}

	// 2) crear token
	raw, err := newRawToken()
	if err != nil {
		log.Error("failed to generate token", logger.Err(err))
		return err
	}
	h := hashToken(raw)

	_, err = tokens.Create(ctx, repository.CreateEmailTokenInput{
		TenantID:   tenantID,
		UserID:     uid,
		Email:      emailStr,
		Type:       repository.EmailTokenVerification,
		TokenHash:  h,
		TTLSeconds: int(s.verifyTTL.Seconds()),
	})
	if err != nil {
		log.Error("failed to persist token", logger.Err(err))
		return err
	}

	// 3) validar redirect (si querés igual que V1)
	if req.RedirectURI != "" && s.cp != nil {
		if !s.cp.ValidateRedirectURI(req.RedirectURI) {
			log.Debug("invalid redirect uri", zap.String("uri", req.RedirectURI))
			return fmt.Errorf("invalid redirect uri")
		}
	}

	// 4) mandar mail via emailv2.Service
	if s.email != nil {
		err = s.email.SendVerificationEmail(ctx, emailv2.SendVerificationRequest{
			TenantSlugOrID: tenantSlug,
			Email:          emailStr,
			Token:          raw,
			ClientID:       req.ClientID,
			RedirectURI:    req.RedirectURI,
			TTL:            s.verifyTTL,
		})
		if err != nil {
			log.Error("failed to send email", logger.Err(err))
			// HOTFIX: Anti-enumeration (soft-fail) si no es authenticated (o siempre)
			// Si userID es nil (public), retornamos nil y logueamos warn
			if userID == nil || *userID == "" {
				log.Warn("failed to send verification email (soft-fail)", logger.Err(err))
				return nil
			}
			return ErrFlowsSendFailed
		}
	} else {
		log.Warn("email service not available, skipping email send")
	}

	log.Info("verify email started", zap.String("user_id", uid))
	return nil
}

func (s *flowsService) VerifyEmailConfirm(ctx context.Context, tda store.TenantDataAccess, req dto.VerifyEmailConfirmRequest) (*dto.VerifyEmailResult, error) {
	log := logger.From(ctx).With(logger.Op("VerifyEmailConfirm"))

	if req.Token == "" {
		return nil, ErrFlowsMissingToken
	}
	if err := tda.RequireDB(); err != nil {
		return nil, ErrFlowsNoDatabase
	}

	// Tenant Consistency Check
	tenantID := tda.ID()
	tenantSlug := tda.Slug()
	if req.TenantID != "" && req.TenantID != tenantID && req.TenantID != tenantSlug {
		return nil, ErrFlowsTenantMismatch
	}

	tokens := tda.EmailTokens()
	if tokens == nil {
		log.Error("email tokens repo not wired")
		return nil, fmt.Errorf("email tokens repo not wired")
	}

	h := hashToken(req.Token)

	tok, err := tokens.GetByHash(ctx, h)
	if err != nil {
		log.Debug("token not found", logger.Err(err))
		return nil, ErrFlowsInvalidToken
	}

	// check token type
	if tok.Type != repository.EmailTokenVerification {
		log.Debug("invalid token type for verification", zap.String("type", string(tok.Type)))
		return nil, ErrFlowsInvalidToken
	}

	// expiración / usado te lo debería validar el repo (ideal), si no:
	if tok.UsedAt != nil || time.Now().After(tok.ExpiresAt) {
		log.Debug("token expired or used")
		return nil, ErrFlowsInvalidToken
	}

	if err := tokens.Use(ctx, h); err != nil {
		log.Debug("failed to use token", logger.Err(err))
		return nil, ErrFlowsInvalidToken
	}

	// marcar email verified
	users := tda.Users()
	if err := users.SetEmailVerified(ctx, tok.UserID, true); err != nil {
		log.Error("failed to set email verified", logger.Err(err))
		return nil, err
	}

	log.Info("email verified", zap.String("user_id", tok.UserID))

	// Validate RedirectURI
	finalRedirect := ""
	if req.RedirectURI != "" && s.cp != nil {
		if s.cp.ValidateRedirectURI(req.RedirectURI) {
			finalRedirect = req.RedirectURI
		} else {
			log.Warn("ignoring unsafe redirect uri", zap.String("uri", req.RedirectURI))
		}
	}

	return &dto.VerifyEmailResult{
		Verified: true,
		Redirect: finalRedirect,
	}, nil
}

func (s *flowsService) ForgotPassword(ctx context.Context, tda store.TenantDataAccess, req dto.ForgotPasswordRequest) error {
	log := logger.From(ctx).With(logger.Op("ForgotPassword"))

	// Tenant Check
	if req.ClientID == "" {
		return ErrFlowsMissingClient
	}
	if req.Email == "" {
		return ErrFlowsMissingEmail
	}
	if err := tda.RequireDB(); err != nil {
		return ErrFlowsNoDatabase
	}

	// Tenant Consistency
	tenantID := tda.ID()
	tenantSlug := tda.Slug()
	if tenantSlug == "" {
		tenantSlug = tenantID
	}
	if req.TenantID != "" && req.TenantID != tenantID && req.TenantID != tenantSlug {
		return ErrFlowsTenantMismatch
	}

	emailStr := strings.ToLower(strings.TrimSpace(req.Email))

	users := tda.Users()
	u, _, err := users.GetByEmail(ctx, tenantID, emailStr)
	if err != nil {
		// anti-enum: ok silencioso
		log.Debug("user lookup failed (anti-enum)", logger.Err(err))
		return nil
	}

	tokens := tda.EmailTokens()
	if tokens == nil {
		log.Error("email tokens repo not wired")
		return fmt.Errorf("email tokens repo not wired")
	}

	raw, err := newRawToken()
	if err != nil {
		return err
	}
	h := hashToken(raw)

	_, err = tokens.Create(ctx, repository.CreateEmailTokenInput{
		TenantID:   tenantID,
		UserID:     u.ID,
		Email:      emailStr,
		Type:       repository.EmailTokenPasswordReset,
		TokenHash:  h,
		TTLSeconds: int(s.resetTTL.Seconds()),
	})
	if err != nil {
		log.Error("failed to create token", logger.Err(err))
		return err
	}

	if s.email != nil {
		// (opcional) si tenés client.ResetPasswordURL desde control plane, pasala como CustomResetURL
		// si no, emailv2.Service arma link al backend /v2/auth/reset
		err = s.email.SendPasswordResetEmail(ctx, emailv2.SendPasswordResetRequest{
			TenantSlugOrID: tenantSlug,
			Email:          emailStr,
			Token:          raw,
			ClientID:       req.ClientID,
			RedirectURI:    req.RedirectURI,
			TTL:            s.resetTTL,
			CustomResetURL: "", // si lo resolvés del client config
		})
		if err != nil {
			log.Warn("failed to send reset email (soft-fail)", logger.Err(err))
			return nil
		}
	}

	log.Info("password reset initiated", zap.String("email", emailStr))
	return nil
}

func (s *flowsService) ResetPassword(ctx context.Context, tda store.TenantDataAccess, req dto.ResetPasswordRequest) (*dto.ResetPasswordResult, error) {
	log := logger.From(ctx).With(logger.Op("ResetPassword"))

	tenantID := tda.ID()
	tenantSlug := tda.Slug()
	if req.TenantID != "" && req.TenantID != tenantID && req.TenantID != tenantSlug {
		return nil, ErrFlowsTenantMismatch
	}
	if req.ClientID == "" {
		return nil, ErrFlowsMissingClient
	}
	if req.Token == "" {
		return nil, ErrFlowsMissingToken
	}
	if req.NewPassword == "" {
		return nil, ErrFlowsMissingPassword
	}
	if err := tda.RequireDB(); err != nil {
		return nil, ErrFlowsNoDatabase
	}

	tokens := tda.EmailTokens()
	if tokens == nil {
		return nil, fmt.Errorf("email tokens repo not wired")
	}

	h := hashToken(req.Token)

	tok, err := tokens.GetByHash(ctx, h)
	if err != nil {
		return nil, ErrFlowsInvalidToken
	}
	// check token type
	if tok.Type != repository.EmailTokenPasswordReset {
		return nil, ErrFlowsInvalidToken
	}

	if tok.UsedAt != nil || time.Now().After(tok.ExpiresAt) {
		return nil, ErrFlowsInvalidToken
	}

	users := tda.Users()
	user, err := users.GetByID(ctx, tok.UserID)
	if err != nil {
		return nil, ErrFlowsUserNotFound
	}

	maxHistory := 0
	if policy := tda.Settings().Security; policy != nil && policy.MaxHistory > 0 {
		maxHistory = policy.MaxHistory
	}

	var prevHashes []string
	if maxHistory > 0 {
		prevHashes, err = users.ListPasswordHistory(ctx, tok.UserID, maxHistory)
		if err != nil {
			return nil, err
		}
	}

	violations := passwordpolicy.Validate(req.NewPassword, tda.Settings().Security, passwordpolicy.ValidationContext{
		Email:        tok.Email,
		Name:         user.Name,
		PreviousHash: prevHashes,
	})
	if len(violations) > 0 {
		return nil, ErrFlowsWeakPassword
	}

	// update password hash (acá usá tu paquete real de hashing V2)
	phash, err := password.Hash(password.Default, req.NewPassword)
	if err != nil {
		return nil, err
	}

	if err := users.RotatePasswordHash(ctx, tok.UserID, phash, maxHistory); err != nil {
		return nil, err
	}

	if err := tokens.Use(ctx, h); err != nil {
		return nil, ErrFlowsInvalidToken
	}

	// revocar refresh (si tu repo lo soporta)
	if tr := tda.Tokens(); tr != nil {
		_, _ = tr.RevokeAllByUser(ctx, tok.UserID, req.ClientID)
	}

	res := &dto.ResetPasswordResult{AutoLogin: false}

	// auto-login opcional (si lo querés como V1)
	if s.autoLogin && s.issuer != nil {
		access, refresh, exp, err := s.issuer.Issue(ctx, tenantID, req.ClientID, tok.UserID)
		if err == nil {
			res.AutoLogin = true
			res.AccessToken = access
			res.RefreshToken = refresh
			res.ExpiresIn = int64(exp)
		} else {
			log.Warn("auto-login failed after reset", logger.Err(err))
		}
	}

	log.Info("password reset completed", zap.String("user_id", tok.UserID))
	return res, nil
}
