// Package auth contains MFA TOTP service.
package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/domain/types"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	adaptive "github.com/dropDatabas3/hellojohn/internal/mfa/adaptive"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	"github.com/dropDatabas3/hellojohn/internal/security/totp"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// MFATOTPService handles MFA TOTP enrollment and verification.
type MFATOTPService interface {
	// Enroll generates a new TOTP secret for a user.
	Enroll(ctx context.Context, tenantSlug, userID, email string) (*EnrollResult, error)

	// Verify confirms TOTP enrollment with a code.
	Verify(ctx context.Context, tenantSlug, userID, code string) (*VerifyResult, error)

	// Disable disables TOTP MFA for a user (requires password + 2FA).
	Disable(ctx context.Context, tenantSlug, userID, password, code, recovery string) error

	// RotateRecovery generates new recovery codes (requires password + 2FA).
	RotateRecovery(ctx context.Context, tenantSlug, userID, password, code, recovery string) (*RotateResult, error)

	// Challenge completes an MFA challenge and issues tokens.
	Challenge(ctx context.Context, tenantSlug string, req ChallengeTOTPRequest) (*ChallengeTOTPResponse, error)
}

// Challenge completes an MFA challenge and issues tokens.
func (s *mfaTOTPService) Challenge(ctx context.Context, tenantSlug string, req ChallengeTOTPRequest) (*ChallengeTOTPResponse, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Op("mfa.totp.challenge"))

	// 1. Validate input
	if req.MFAToken == "" {
		return nil, ErrMFAMissingFields
	}
	if req.Code == "" && req.Recovery == "" {
		return nil, ErrMFAMissingFields
	}

	// 2. Resolve/Validate Tenant
	// The token was issued for a specific tenant. Ensure request matches.
	// If tenantSlug is provided (from URL), it must match ch.TenantID (or resolving ID).
	// For simplify, we assume tenantSlug is the slug, so we need to resolve ID or vice-versa.
	// However, ch.TenantID is usually the UUID in V1.
	// Let's resolve the tenantSlug to ID using DAL.
	// Actually, DAL resolution is already done in controller middleware if routed by tenant.
	// We can cross check.
	tda, err := s.dal.ForTenant(ctx, tenantSlug)
	if err != nil {
		return nil, ErrMFATenantMismatch
	}

	// 3. Get pending challenge from tenant-scoped cache
	key := "mfa:token:" + strings.TrimSpace(req.MFAToken)
	cacheRepo := tda.Cache()
	payloadStr, err := cacheRepo.Get(ctx, key)
	if err != nil {
		if cache.IsNotFound(err) {
			return nil, ErrMFATokenNotFound
		}
		log.Error("failed to get mfa token from cache", logger.Err(err))
		return nil, ErrMFAStoreFailed
	}

	var ch mfaChallenge
	if err := json.Unmarshal([]byte(payloadStr), &ch); err != nil {
		log.Error("failed to unmarshal mfa challenge", logger.Err(err))
		return nil, ErrMFATokenInvalid
	}

	if tda.ID() != ch.TenantID {
		// Try to match if tenantSlug passed is "global" (FS admin scenarios?)
		// But in V2 we are strict.
		log.Warn("tenant mismatch in mfa challenge",
			logger.String("req_tenant", tenantSlug),
			logger.String("token_tid", ch.TenantID))
		return nil, ErrMFATenantMismatch
	}

	// 4. Validate credentials (DB access)
	mfaRepo := tda.MFA()
	if mfaRepo == nil {
		return nil, ErrMFANotSupported
	}

	userID := ch.UserID
	usingRecovery := strings.TrimSpace(req.Recovery) != ""
	if usingRecovery {
		rateLimited, rlErr := s.isRecoveryRateLimited(ctx, cacheRepo, ch.TenantID, userID)
		if rlErr != nil {
			// Fail-open: cache errors must not block MFA challenge.
			log.Warn("failed to check recovery code rate limit", logger.Err(rlErr))
		} else if rateLimited {
			return nil, ErrRecoveryCodeRateLimited
		}
	}
	if err := s.validate2FA(ctx, mfaRepo, userID, req.Code, req.Recovery); err != nil {
		if usingRecovery && errors.Is(err, ErrMFAInvalidCode) {
			if rlErr := s.incrementRecoveryRateLimit(ctx, cacheRepo, ch.TenantID, userID); rlErr != nil {
				// Fail-open: cache errors must not block MFA challenge.
				log.Warn("failed to increment recovery code rate limit", logger.Err(rlErr))
			}
		}
		return nil, err
	}

	// 5. Remember device (optional)
	deviceToken := ""
	if req.RememberDevice {
		rawDev, err := tokens.GenerateOpaqueToken(32)
		if err != nil {
			log.Warn("failed to generate trusted device token", logger.Err(err))
		} else {
			devHash := tokens.SHA256Base64URL(rawDev)
			expiresAt := time.Now().UTC().Add(30 * 24 * time.Hour)
			if err := mfaRepo.AddTrustedDevice(ctx, userID, devHash, expiresAt); err != nil {
				log.Warn("failed to persist trusted device", logger.Err(err))
			} else {
				deviceToken = rawDev
			}
		}
	}

	// 6. Issue Tokens
	// Replicate issuance logic.
	// Claims: tid, amr, acr, scp
	amr := append(ch.AMRBase, "mfa")
	acr := "urn:hellojohn:loa:2"

	std := map[string]any{
		"tid": ch.TenantID,
		"amr": amr,
		"acr": acr,
		"scp": strings.Join(ch.Scope, " "),
	}
	custom := map[string]any{}

	// Claims Hook
	if s.claimsHook != nil {
		std, custom = s.claimsHook.ApplyAccess(ctx, ch.TenantID, ch.ClientID, userID, ch.Scope, amr, std, custom)
	}

	// Resolve Issuer (Key selection)
	settings := tda.Settings()
	effIss := jwtx.ResolveIssuer(
		s.issuer.Iss,
		string(settings.IssuerMode),
		tda.Slug(),
		settings.IssuerOverride,
	)

	var kid string
	var priv any
	var errKey error

	if types.IssuerMode(settings.IssuerMode) == types.IssuerModePath {
		kid, priv, _, errKey = s.issuer.Keys.ActiveForTenant(tda.Slug())
	} else {
		kid, priv, _, errKey = s.issuer.Keys.Active()
	}

	if errKey != nil {
		log.Error("failed to get active key", logger.Err(errKey))
		return nil, ErrMFACryptoFailed
	}

	now := time.Now().UTC()
	exp := now.Add(s.issuer.AccessTTL)

	claims := jwtv5.MapClaims{
		"iss": effIss,
		"sub": userID,
		"aud": ch.ClientID,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": exp.Unix(),
	}
	for k, v := range std {
		claims[k] = v
	}
	if len(custom) > 0 {
		claims["custom"] = custom
	}

	token := jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid
	token.Header["typ"] = "JWT"
	signedAccessToken, err := token.SignedString(priv)
	if err != nil {
		log.Error("failed to sign access token", logger.Err(err))
		return nil, ErrMFACryptoFailed
	}

	// Refresh Token
	rawRT, err := tokens.GenerateOpaqueToken(32)
	if err != nil {
		return nil, ErrMFACryptoFailed
	}

	// Persist Refresh Token
	// Prefer CreateRefreshTokenTC (tenant+client) if available.
	// tda.Tokens() returns TokenRepository.
	tokenRepo := tda.Tokens()
	if tokenRepo == nil {
		return nil, ErrMFANotSupported
	}

	rtHash := tokens.SHA256Base64URL(rawRT)

	_, err = tokenRepo.Create(ctx, repository.CreateRefreshTokenInput{
		TenantID:   ch.TenantID,
		ClientID:   ch.ClientID,
		UserID:     userID,
		TokenHash:  rtHash,
		TTLSeconds: int(s.refreshTTL.Seconds()),
	})
	if err != nil {
		log.Error("failed to create refresh token", logger.Err(err))
		return nil, ErrMFAStoreFailed
	}

	// 7. Success - Delete cache
	if err := cacheRepo.Delete(ctx, key); err != nil {
		log.Warn("failed to delete mfa challenge cache key", logger.Err(err))
	}
	if err := adaptive.SaveSuccessState(
		ctx,
		cacheRepo,
		ch.TenantID,
		userID,
		mw.GetClientIP(ctx),
		mw.GetUserAgent(ctx),
		s.adaptiveStateTTL,
	); err != nil {
		log.Warn("failed to persist adaptive success state", logger.Err(err))
	}

	// Audit: MFA challenge completed
	if s.auditBus != nil {
		s.auditBus.Emit(
			audit.NewEvent(audit.EventLogin, tda.ID()).
				WithActor(userID, audit.ActorUser).
				WithTarget(userID, audit.TargetUser).
				WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx)).
				WithMeta("method", "mfa_totp").
				WithMeta("client_id", ch.ClientID),
		)
	}

	return &ChallengeTOTPResponse{
		AccessToken:  signedAccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.issuer.AccessTTL.Seconds()),
		RefreshToken: rawRT,
		DeviceToken:  deviceToken,
	}, nil
}

// ChallengeTOTPRequest maps to dto.ChallengeTOTPRequest
type ChallengeTOTPRequest struct {
	MFAToken       string
	Code           string
	Recovery       string
	RememberDevice bool
}

// ChallengeTOTPResponse maps to dto.ChallengeTOTPResponse
type ChallengeTOTPResponse struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int64
	RefreshToken string
	DeviceToken  string
}

// mfaChallenge represents the cached data for a pending MFA challenge.
// Must match V1 structure to be compatible.
type mfaChallenge struct {
	UserID   string   `json:"uid"`
	TenantID string   `json:"tid"`
	ClientID string   `json:"cid"`
	AMRBase  []string `json:"amr"`
	Scope    []string `json:"scp"`
}

// EnrollResult contains the TOTP enrollment data.
type EnrollResult struct {
	SecretBase32 string
	OTPAuthURL   string
}

// VerifyResult contains the verification outcome.
type VerifyResult struct {
	Enabled       bool
	RecoveryCodes []string
}

// RotateResult contains the new recovery codes.
type RotateResult struct {
	RecoveryCodes []string
}

// MFA errors
var (
	ErrMFANotInitialized       = errors.New("mfa not initialized")
	ErrMFAInvalidCode          = errors.New("invalid mfa code")
	ErrRecoveryCodeRateLimited = errors.New("recovery code rate limit exceeded")
	ErrMFACryptoFailed         = errors.New("mfa crypto failed")
	ErrMFAStoreFailed          = errors.New("mfa store failed")
	ErrMFANotSupported         = errors.New("mfa not supported for tenant")
	ErrMFAInvalidPassword      = errors.New("invalid password")
	ErrMFAUserNotFound         = errors.New("user not found")
	ErrMFAMissingFields        = errors.New("missing required fields")
	ErrMFATokenNotFound        = errors.New("mfa token not found or expired")
	ErrMFATokenInvalid         = errors.New("mfa token invalid")
	ErrMFATenantMismatch       = errors.New("tenant mismatch")
)

const (
	recoveryRateLimitKeyFmt = "rl:mfa:recovery:%s:%s"
	recoveryRateLimitMax    = 10
	recoveryRateLimitWindow = 24 * time.Hour
)

// MFATOTPDeps contains dependencies for MFATOTPService.
type MFATOTPDeps struct {
	DAL              store.DataAccessLayer
	Issuer           *jwtx.Issuer
	Cache            cache.Client
	RefreshTTL       time.Duration
	ClaimsHook       ClaimsHook
	MasterKey        string
	TOTPWindow       int    // TOTP validation window (±N), default 1
	TOTPIssuer       string // TOTP app display name, default "HelloJohn"
	AdaptiveStateTTL time.Duration
	AuditBus         *audit.AuditBus
}

// mfaTOTPService implements MFATOTPService.
type mfaTOTPService struct {
	dal              store.DataAccessLayer
	issuer           *jwtx.Issuer
	cache            cache.Client
	refreshTTL       time.Duration
	claimsHook       ClaimsHook
	masterKey        string
	totpWindow       int
	totpIssuer       string
	adaptiveStateTTL time.Duration
	auditBus         *audit.AuditBus
}

// NewMFATOTPService creates a new MFATOTPService.
func NewMFATOTPService(d MFATOTPDeps) MFATOTPService {
	window := d.TOTPWindow
	if window <= 0 || window > 3 {
		window = 1
	}
	issuerName := d.TOTPIssuer
	if issuerName == "" {
		issuerName = "HelloJohn"
	}
	adaptiveStateTTL := d.AdaptiveStateTTL
	if adaptiveStateTTL <= 0 {
		adaptiveStateTTL = adaptive.DefaultStateTTL
	}
	return &mfaTOTPService{
		dal:              d.DAL,
		issuer:           d.Issuer,
		cache:            d.Cache,
		refreshTTL:       d.RefreshTTL,
		claimsHook:       d.ClaimsHook,
		masterKey:        d.MasterKey,
		totpWindow:       window,
		totpIssuer:       issuerName,
		adaptiveStateTTL: adaptiveStateTTL,
		auditBus:         d.AuditBus,
	}
}

// Enroll generates a new TOTP secret for a user.
func (s *mfaTOTPService) Enroll(ctx context.Context, tenantSlug, userID, email string) (*EnrollResult, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Op("mfa.totp.enroll"))

	// Get tenant data access
	tda, err := s.dal.ForTenant(ctx, tenantSlug)
	if err != nil {
		log.Warn("tenant data access not available", logger.TenantID(tenantSlug))
		return nil, ErrMFANotSupported
	}

	// Require DB for MFA
	if err := tda.RequireDB(); err != nil {
		log.Warn("tenant has no DB", logger.TenantID(tenantSlug))
		return nil, ErrMFANotSupported
	}

	// Generate TOTP secret
	_, b32, err := totp.GenerateSecret()
	if err != nil {
		log.Error("failed to generate TOTP secret", logger.Err(err))
		return nil, ErrMFACryptoFailed
	}

	// Encrypt secret
	enc, err := s.aesgcmEncryptMFA([]byte(b32))
	if err != nil {
		log.Error("failed to encrypt TOTP secret", logger.Err(err))
		return nil, ErrMFACryptoFailed
	}

	// Store encrypted secret
	mfaRepo := tda.MFA()
	if mfaRepo == nil {
		log.Warn("MFA repository not available")
		return nil, ErrMFANotSupported
	}

	if err := mfaRepo.UpsertTOTP(ctx, userID, enc); err != nil {
		log.Error("failed to store TOTP secret", logger.Err(err))
		return nil, ErrMFAStoreFailed
	}

	// Build otpauth URL
	issuer := s.resolveIssuer(tda)
	otpauthURL := totp.OTPAuthURL(issuer, email, b32)

	log.Info("TOTP enrolled", logger.TenantID(tenantSlug), logger.UserID(userID))

	// Audit: MFA enrolled
	if s.auditBus != nil {
		s.auditBus.Emit(
			audit.NewEvent(audit.EventMFAEnroll, tda.ID()).
				WithActor(userID, audit.ActorUser).
				WithTarget(userID, audit.TargetUser).
				WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx)).
				WithMeta("method", "totp"),
		)
	}

	return &EnrollResult{
		SecretBase32: b32,
		OTPAuthURL:   otpauthURL,
	}, nil
}

// Verify confirms TOTP enrollment with a code.
func (s *mfaTOTPService) Verify(ctx context.Context, tenantSlug, userID, code string) (*VerifyResult, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Op("mfa.totp.verify"))

	if strings.TrimSpace(code) == "" {
		return nil, ErrMFAInvalidCode
	}

	// Get tenant data access
	tda, err := s.dal.ForTenant(ctx, tenantSlug)
	if err != nil {
		return nil, ErrMFANotSupported
	}

	mfaRepo := tda.MFA()
	if mfaRepo == nil {
		return nil, ErrMFANotSupported
	}

	// Get TOTP config
	mfaCfg, err := mfaRepo.GetTOTP(ctx, userID)
	if err != nil || mfaCfg == nil {
		log.Warn("TOTP not initialized for user")
		return nil, ErrMFANotInitialized
	}

	// Decrypt secret
	plain, err := s.aesgcmDecryptMFA(mfaCfg.SecretEncrypted)
	if err != nil {
		log.Error("failed to decrypt TOTP secret", logger.Err(err))
		return nil, ErrMFACryptoFailed
	}

	// Decode base32
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(plain))
	if err != nil {
		log.Error("failed to decode TOTP secret", logger.Err(err))
		return nil, ErrMFACryptoFailed
	}

	// Get last counter for replay protection
	var lastCounter *int64
	if mfaCfg.LastUsedAt != nil {
		c := mfaCfg.LastUsedAt.Unix() / 30
		lastCounter = &c
	}

	// Verify code
	window := s.totpWindow
	ok, counter := totp.Verify(raw, code, time.Now(), window, lastCounter)
	if !ok {
		log.Warn("invalid TOTP code")
		return nil, ErrMFAInvalidCode
	}

	// Update last used
	_ = mfaRepo.UpdateTOTPUsedAt(ctx, userID)

	// Check if first confirmation
	firstTime := mfaCfg.ConfirmedAt == nil

	// Confirm TOTP
	if err := mfaRepo.ConfirmTOTP(ctx, userID); err != nil {
		log.Error("failed to confirm TOTP", logger.Err(err))
		// Don't fail, MFA is still valid
	}

	result := &VerifyResult{Enabled: true}

	// Generate recovery codes on first verification
	if firstTime {
		recPlain, recHashes, err := generateRecoveryCodes(10)
		if err == nil {
			if err := mfaRepo.SetRecoveryCodes(ctx, userID, recHashes); err == nil {
				result.RecoveryCodes = recPlain
			}
		}
	}

	log.Info("TOTP verified",
		logger.TenantID(tenantSlug),
		logger.UserID(userID),
		logger.Bool("first_time", firstTime),
		zap.Int64("counter", counter),
	)

	// Audit: MFA verified
	if s.auditBus != nil {
		s.auditBus.Emit(
			audit.NewEvent(audit.EventMFAVerify, tda.ID()).
				WithActor(userID, audit.ActorUser).
				WithTarget(userID, audit.TargetUser).
				WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx)).
				WithMeta("method", "totp").
				WithMeta("first_time", firstTime),
		)
	}

	return result, nil
}

// Disable disables TOTP MFA for a user (requires password + 2FA).
func (s *mfaTOTPService) Disable(ctx context.Context, tenantSlug, userID, password, code, recovery string) error {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Op("mfa.totp.disable"))

	// Validate inputs
	if strings.TrimSpace(password) == "" {
		return ErrMFAMissingFields
	}
	if strings.TrimSpace(code) == "" && strings.TrimSpace(recovery) == "" {
		return ErrMFAMissingFields
	}

	// Get tenant data access
	tda, err := s.dal.ForTenant(ctx, tenantSlug)
	if err != nil {
		return ErrMFANotSupported
	}

	mfaRepo := tda.MFA()
	if mfaRepo == nil {
		return ErrMFANotSupported
	}

	// Validate password via users repo
	usersRepo := tda.Users()
	if usersRepo == nil {
		return ErrMFANotSupported
	}

	user, err := usersRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		log.Warn("user not found", logger.UserID(userID))
		return ErrMFAUserNotFound
	}

	// Get identity with password hash via GetByEmail
	_, identity, err := usersRepo.GetByEmail(ctx, user.TenantID, user.Email)
	if err != nil || identity == nil || identity.PasswordHash == nil {
		log.Warn("no password identity")
		return ErrMFAInvalidPassword
	}

	// Check password using repo method
	if !usersRepo.CheckPassword(identity.PasswordHash, password) {
		log.Warn("invalid password")
		return ErrMFAInvalidPassword
	}

	// Validate 2FA
	if err := s.validate2FA(ctx, mfaRepo, userID, code, recovery); err != nil {
		return err
	}

	// Disable TOTP
	if err := mfaRepo.DisableTOTP(ctx, userID); err != nil {
		log.Error("failed to disable TOTP", logger.Err(err))
		return ErrMFAStoreFailed
	}

	log.Info("TOTP disabled", logger.TenantID(tenantSlug), logger.UserID(userID))

	// Audit: MFA disabled
	if s.auditBus != nil {
		s.auditBus.Emit(
			audit.NewEvent(audit.EventMFADisable, tda.ID()).
				WithActor(userID, audit.ActorUser).
				WithTarget(userID, audit.TargetUser).
				WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx)).
				WithMeta("method", "totp"),
		)
	}

	return nil
}

// RotateRecovery generates new recovery codes (requires password + 2FA).
func (s *mfaTOTPService) RotateRecovery(ctx context.Context, tenantSlug, userID, password, code, recovery string) (*RotateResult, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Op("mfa.recovery.rotate"))

	// Validate inputs
	if strings.TrimSpace(password) == "" {
		return nil, ErrMFAMissingFields
	}
	if strings.TrimSpace(code) == "" && strings.TrimSpace(recovery) == "" {
		return nil, ErrMFAMissingFields
	}

	// Get tenant data access
	tda, err := s.dal.ForTenant(ctx, tenantSlug)
	if err != nil {
		return nil, ErrMFANotSupported
	}

	mfaRepo := tda.MFA()
	if mfaRepo == nil {
		return nil, ErrMFANotSupported
	}

	// Validate password
	usersRepo := tda.Users()
	if usersRepo == nil {
		return nil, ErrMFANotSupported
	}

	user, err := usersRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, ErrMFAUserNotFound
	}

	// Get identity with password hash via GetByEmail
	_, identity, err := usersRepo.GetByEmail(ctx, user.TenantID, user.Email)
	if err != nil || identity == nil || identity.PasswordHash == nil {
		return nil, ErrMFAInvalidPassword
	}

	// Check password using repo method
	if !usersRepo.CheckPassword(identity.PasswordHash, password) {
		return nil, ErrMFAInvalidPassword
	}

	// Validate 2FA
	if err := s.validate2FA(ctx, mfaRepo, userID, code, recovery); err != nil {
		return nil, err
	}

	// Delete old recovery codes
	_ = mfaRepo.DeleteRecoveryCodes(ctx, userID)

	// Generate new recovery codes
	recPlain, recHashes, err := generateRecoveryCodes(10)
	if err != nil {
		log.Error("failed to generate recovery codes", logger.Err(err))
		return nil, ErrMFACryptoFailed
	}

	if err := mfaRepo.SetRecoveryCodes(ctx, userID, recHashes); err != nil {
		log.Error("failed to store recovery codes", logger.Err(err))
		return nil, ErrMFAStoreFailed
	}

	log.Info("recovery codes rotated", logger.TenantID(tenantSlug), logger.UserID(userID))

	return &RotateResult{RecoveryCodes: recPlain}, nil
}

// validate2FA validates either TOTP code or recovery code.
func (s *mfaTOTPService) validate2FA(ctx context.Context, mfaRepo mfaRepository, userID, code, recovery string) error {
	if strings.TrimSpace(recovery) != "" {
		// Use recovery code
		hash := tokens.SHA256Base64URL(strings.TrimSpace(recovery))
		ok, err := mfaRepo.UseRecoveryCode(ctx, userID, hash)
		if err != nil {
			return ErrMFAStoreFailed
		}
		if !ok {
			return ErrMFAInvalidCode
		}
		return nil
	}

	// Validate TOTP
	mfaCfg, err := mfaRepo.GetTOTP(ctx, userID)
	if err != nil || mfaCfg == nil || mfaCfg.ConfirmedAt == nil {
		return ErrMFANotInitialized
	}

	plain, err := s.aesgcmDecryptMFA(mfaCfg.SecretEncrypted)
	if err != nil {
		return ErrMFACryptoFailed
	}

	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(plain))
	if err != nil {
		return ErrMFACryptoFailed
	}

	var lastCounter *int64
	if mfaCfg.LastUsedAt != nil {
		c := mfaCfg.LastUsedAt.Unix() / 30
		lastCounter = &c
	}

	ok, counter := totp.Verify(raw, strings.TrimSpace(code), time.Now(), s.totpWindow, lastCounter)
	if !ok {
		return ErrMFAInvalidCode
	}

	// Update last used
	_ = mfaRepo.UpdateTOTPUsedAt(ctx, userID)
	_ = counter // Used for anti-replay, logged by caller if needed

	return nil
}

// mfaRepository defines the MFA operations needed by this service.
// This is a local interface to avoid importing the full repository package in the method signature.
type mfaRepository interface {
	GetTOTP(ctx context.Context, userID string) (*repository.MFATOTP, error)
	UseRecoveryCode(ctx context.Context, userID, hash string) (bool, error)
	UpdateTOTPUsedAt(ctx context.Context, userID string) error
	DisableTOTP(ctx context.Context, userID string) error
	DeleteRecoveryCodes(ctx context.Context, userID string) error
	SetRecoveryCodes(ctx context.Context, userID string, hashes []string) error
	AddTrustedDevice(ctx context.Context, userID, deviceHash string, expiresAt time.Time) error
	IsTrustedDevice(ctx context.Context, userID, deviceHash string) (bool, error)
}

// --- Crypto helpers (same algorithm as V1) ---

const gcmPrefixMFA = "GCMV1-MFA:"

func (s *mfaTOTPService) aesgcmEncryptMFA(plain []byte) (string, error) {
	if len(s.masterKey) < 32 {
		return "", errors.New("missing or short MasterKey (need 32 bytes)")
	}

	block, err := aes.NewCipher([]byte(s.masterKey)[:32])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ct := gcm.Seal(nil, nonce, plain, nil)
	out := append(nonce, ct...)
	return gcmPrefixMFA + hex.EncodeToString(out), nil
}

func (s *mfaTOTPService) aesgcmDecryptMFA(enc string) ([]byte, error) {
	if !strings.HasPrefix(enc, gcmPrefixMFA) {
		return nil, errors.New("bad prefix")
	}

	raw, err := hex.DecodeString(strings.TrimPrefix(enc, gcmPrefixMFA))
	if err != nil {
		return nil, err
	}

	if len(s.masterKey) < 32 {
		return nil, errors.New("missing or short MasterKey (need 32 bytes)")
	}

	block, err := aes.NewCipher([]byte(s.masterKey)[:32])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ns := gcm.NonceSize()
	if len(raw) < ns {
		return nil, errors.New("ciphertext too short")
	}

	return gcm.Open(nil, raw[:ns], raw[ns:], nil)
}

type recoveryRateLimitState struct {
	Count   int       `json:"count"`
	ResetAt time.Time `json:"reset_at"`
}

func (s *mfaTOTPService) isRecoveryRateLimited(ctx context.Context, cacheRepo cache.Client, tenantID, userID string) (bool, error) {
	state, _, err := loadRecoveryRateLimitState(ctx, cacheRepo, tenantID, userID)
	if err != nil {
		return false, err
	}
	if state == nil {
		return false, nil
	}
	return state.Count >= recoveryRateLimitMax, nil
}

func (s *mfaTOTPService) incrementRecoveryRateLimit(ctx context.Context, cacheRepo cache.Client, tenantID, userID string) error {
	now := time.Now().UTC()
	state, _, err := loadRecoveryRateLimitState(ctx, cacheRepo, tenantID, userID)
	if err != nil {
		return err
	}

	if state == nil {
		state = &recoveryRateLimitState{
			Count:   1,
			ResetAt: now.Add(recoveryRateLimitWindow),
		}
	} else {
		state.Count++
	}

	ttl := time.Until(state.ResetAt)
	if ttl <= 0 {
		state.Count = 1
		state.ResetAt = now.Add(recoveryRateLimitWindow)
		ttl = recoveryRateLimitWindow
	}

	payload, err := json.Marshal(state)
	if err != nil {
		return nil // Fail-open on serialization errors.
	}

	key := fmt.Sprintf(recoveryRateLimitKeyFmt, tenantID, userID)
	return cacheRepo.Set(ctx, key, string(payload), ttl)
}

func loadRecoveryRateLimitState(ctx context.Context, cacheRepo cache.Client, tenantID, userID string) (*recoveryRateLimitState, time.Duration, error) {
	key := fmt.Sprintf(recoveryRateLimitKeyFmt, tenantID, userID)
	raw, err := cacheRepo.Get(ctx, key)
	if err != nil {
		if cache.IsNotFound(err) {
			return nil, 0, nil
		}
		return nil, 0, err
	}

	// Backward compatibility: if a plain integer is present, interpret it as count.
	if parsed, parseErr := strconv.Atoi(strings.TrimSpace(raw)); parseErr == nil {
		state := &recoveryRateLimitState{
			Count:   parsed,
			ResetAt: time.Now().UTC().Add(recoveryRateLimitWindow),
		}
		return state, recoveryRateLimitWindow, nil
	}

	var state recoveryRateLimitState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return nil, 0, nil // Fail-open on malformed cache payload.
	}

	now := time.Now().UTC()
	if state.ResetAt.IsZero() || !state.ResetAt.After(now) {
		_ = cacheRepo.Delete(ctx, key)
		return nil, 0, nil
	}

	return &state, time.Until(state.ResetAt), nil
}

// --- Recovery code generation ---

const recoveryAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no I, O, 0, 1

func generateRecoveryCodes(count int) ([]string, []string, error) {
	plain := make([]string, count)
	hashes := make([]string, count)

	for i := 0; i < count; i++ {
		code := make([]byte, 10)
		for j := 0; j < 10; j++ {
			b := make([]byte, 1)
			if _, err := rand.Read(b); err != nil {
				return nil, nil, err
			}
			code[j] = recoveryAlphabet[int(b[0])%len(recoveryAlphabet)]
		}
		plain[i] = string(code)
		hashes[i] = tokens.SHA256Base64URL(string(code))
	}

	return plain, hashes, nil
}

func (s *mfaTOTPService) resolveIssuer(tda store.TenantDataAccess) string {
	settings := tda.Settings()
	if settings != nil && settings.MFA != nil && strings.TrimSpace(settings.MFA.TOTPIssuer) != "" {
		return strings.TrimSpace(settings.MFA.TOTPIssuer)
	}
	return s.totpIssuer
}
