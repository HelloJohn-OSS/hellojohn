package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/domain/types"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	"github.com/dropDatabas3/hellojohn/internal/http/helpers"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"github.com/dropDatabas3/hellojohn/internal/passwordpolicy"
	"github.com/dropDatabas3/hellojohn/internal/security/password"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	bot "github.com/dropDatabas3/hellojohn/internal/http/services/bot"
)

// RegisterService defines operations for user registration.
type RegisterService interface {
	Register(ctx context.Context, in dto.RegisterRequest) (*dto.RegisterResult, error)
}

// VerificationSender defines operation to send verification emails.
type VerificationSender interface {
	SendVerification(ctx context.Context, tenantSlugOrID, clientID, userID, email, redirect string) error
}

// RegisterDeps contains dependencies for the register service.
type RegisterDeps struct {
	DAL           store.DataAccessLayer
	Issuer        *jwtx.Issuer
	RefreshTTL    time.Duration
	ClaimsHook    ClaimsHook
	BlacklistPath string
	AutoLogin     bool
	// FSAdminEnabled allows registration without tenant/client (FS-admin mode).
	FSAdminEnabled bool

	// VerificationSender sends validation emails (soft fail)
	VerificationSender VerificationSender

	AuditBus *audit.AuditBus

	// BotProtection valida tokens anti-bot antes de crear el usuario.
	// Si nil, se omite la validación (equivalente a NoopService).
	BotProtection bot.BotProtectionService

	// Password Policy fallback chain configuration.
	PasswordPolicyGlobalTenant string
	PasswordPolicyEnv          *repository.SecurityPolicy
}

type registerService struct {
	deps RegisterDeps
}

// NewRegisterService creates a new register service.
func NewRegisterService(deps RegisterDeps) RegisterService {
	if deps.ClaimsHook == nil {
		deps.ClaimsHook = NoOpClaimsHook{}
	}
	return &registerService{deps: deps}
}

// Register errors
// Register errors (sentinel)
var (
	ErrRegisterMissingFields           = errors.New("missing required fields")
	ErrRegisterInvalidClient           = errors.New("invalid client")
	ErrRegisterPasswordNotAllowed      = errors.New("password registration not allowed for this client")
	ErrRegisterEmailTaken              = errors.New("email already registered")
	ErrRegisterPolicyViolation         = errors.New("password policy violation")
	ErrRegisterHashFailed              = errors.New("failed to hash password")
	ErrRegisterCreateFailed            = errors.New("failed to create user")
	ErrRegisterTokenFailed             = errors.New("failed to issue tokens")
	ErrRegisterVerificationUnavailable = errors.New("email verification delivery unavailable")
	ErrRegisterFSAdminNotAvailable     = errors.New("fs-admin registration not available in v2")
)

func (s *registerService) Register(ctx context.Context, in dto.RegisterRequest) (*dto.RegisterResult, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("auth.register"),
		logger.Op("Register"),
	)

	// Paso 0: Bot protection — validar antes de crear el usuario
	if s.deps.BotProtection != nil {
		if err := s.deps.BotProtection.Validate(ctx, bot.ValidateRequest{
			Token:      in.TurnstileToken,
			RemoteIP:   in.RemoteIP,
			TenantSlug: in.TenantID,
			Endpoint:   "register",
		}); err != nil {
			switch {
			case errors.Is(err, bot.ErrTokenMissing):
				return nil, httperrors.ErrBotTokenMissing
			default:
				return nil, httperrors.ErrBotVerificationFailed
			}
		}
	}

	// Normalize inputs
	in.Email = strings.TrimSpace(strings.ToLower(in.Email))
	in.TenantID = strings.TrimSpace(in.TenantID)
	in.ClientID = strings.TrimSpace(in.ClientID)

	// Validate required fields
	if in.Email == "" || in.Password == "" {
		return nil, ErrRegisterMissingFields
	}

	// Check for FS-admin mode (only if BOTH are missing)
	if in.TenantID == "" && in.ClientID == "" {
		if s.deps.FSAdminEnabled {
			return s.registerFSAdmin(ctx, in, log)
		}
		return nil, ErrRegisterFSAdminNotAvailable
	}

	// If only one missing, it's an inconsistent request
	if in.TenantID == "" || in.ClientID == "" {
		return nil, ErrRegisterMissingFields
	}

	// Standard tenant-based registration
	return s.registerTenantUser(ctx, in, log)
}

// registerFSAdmin handles FS-admin registration (global, no tenant).
// TODO: Migrate fs_admin.go helpers from V1 to V2 before enabling this.
func (s *registerService) registerFSAdmin(ctx context.Context, in dto.RegisterRequest, log *zap.Logger) (*dto.RegisterResult, error) {
	log.Debug("FS-admin registration mode - not yet implemented in V2")
	// FS-admin mode requires helpers.FSAdminRegister from V1 to be migrated.
	// For now, return error indicating this mode is not available in V2.
	return nil, ErrRegisterFSAdminNotAvailable
}

// registerTenantUser handles standard tenant-based user registration.
func (s *registerService) registerTenantUser(ctx context.Context, in dto.RegisterRequest, log *zap.Logger) (*dto.RegisterResult, error) {
	// Resolve tenant
	tda, err := s.deps.DAL.ForTenant(ctx, in.TenantID)
	if err != nil {
		log.Debug("tenant resolution failed", logger.Err(err))
		return nil, ErrRegisterInvalidClient
	}

	tenantSlug := tda.Slug()
	tenantID := tda.ID()
	log = log.With(logger.TenantSlug(tenantSlug))

	// Require DB for user creation
	if err := tda.RequireDB(); err != nil {
		log.Debug("tenant DB not available", logger.Err(err))
		return nil, ErrNoDatabase
	}

	// Resolve client
	client, err := tda.Clients().Get(ctx, in.ClientID)
	if err != nil {
		log.Debug("client not found", logger.Err(err))
		return nil, ErrRegisterInvalidClient
	}

	// Provider gating: check if password registration is allowed
	if !helpers.IsPasswordProviderAllowed(client.Providers) {
		log.Debug("password provider not allowed for client")
		return nil, ErrRegisterPasswordNotAllowed
	}

	// Password policy: tenant > global control plane > env > default.
	resolvedPolicy, resolveErr := passwordpolicy.ResolveForTenant(
		ctx,
		s.deps.DAL,
		in.TenantID,
		s.deps.PasswordPolicyGlobalTenant,
		s.deps.PasswordPolicyEnv,
	)
	if resolveErr != nil {
		log.Debug("failed to resolve effective password policy", logger.Err(resolveErr))
		return nil, ErrRegisterInvalidClient
	}
	if err := s.checkPasswordPolicy(ctx, in.Password, in.Email, "", &resolvedPolicy.Policy); err != nil {
		log.Debug("password policy violation", logger.Err(err))
		return nil, err // Return the error directly to preserve the detailed message
	}

	// Hash password
	phc, err := password.Hash(password.Default, in.Password)
	if err != nil {
		log.Error("password hash failed", logger.Err(err))
		return nil, ErrRegisterHashFailed
	}

	// Create user (UserRepository.Create creates user + password identity together)
	userInput := repository.CreateUserInput{
		TenantID:       tenantID,
		Email:          in.Email,
		PasswordHash:   phc,
		CustomFields:   in.CustomFields,
		SourceClientID: in.ClientID,
	}

	user, _, err := tda.Users().Create(ctx, userInput)
	if err != nil {
		if errors.Is(err, repository.ErrConflict) {
			log.Debug("email already exists")
			return nil, ErrRegisterEmailTaken
		}
		log.Error("user creation failed", logger.Err(err))
		return nil, fmt.Errorf("%w: %w", ErrRegisterCreateFailed, err)
	}

	log = log.With(logger.UserID(user.ID))

	// Audit: user registered
	if s.deps.AuditBus != nil {
		s.deps.AuditBus.Emit(
			audit.NewEvent(audit.EventRegister, tenantID).
				WithActor(user.ID, audit.ActorUser).
				WithTarget(user.ID, audit.TargetUser).
				WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx)).
				WithMeta("client_id", in.ClientID).
				WithMeta("method", "password"),
		)
	}

	// Email verification (soft fail, matching V1 behavior)
	// Email verification (soft fail, matching V1 behavior)
	if s.deps.VerificationSender != nil &&
		helpers.IsPasswordProviderAllowed(client.Providers) &&
		client.RequireEmailVerification {
		// Note: V1 checked client.RequireEmailVerification here.
		// Assuming we want to send it if configured.
		// TODO: Add RequireEmailVerification to Client model if missing.
		// For now, we attempt send if sender is wired.
		if err := s.deps.VerificationSender.SendVerification(ctx, tenantSlug, in.ClientID, user.ID, in.Email, ""); err != nil {
			log.Warn("verification email failed (soft)", logger.Err(err))
		}
	}

	// If no auto-login, return just user_id
	if !s.deps.AutoLogin {
		log.Info("user registered (no auto-login)")
		return &dto.RegisterResult{UserID: user.ID}, nil
	}

	// Auto-login: issue tokens
	return s.issueTokens(ctx, tda, user.ID, in.ClientID, client.Scopes, log)
}

// issueTokens issues access and refresh tokens after registration.
func (s *registerService) issueTokens(ctx context.Context, tda store.TenantDataAccess, userID, clientID string, scopes []string, log *zap.Logger) (*dto.RegisterResult, error) {
	tenantID := tda.ID()
	tenantSlug := tda.Slug()

	// Build claims
	amr := []string{"pwd"}
	std := map[string]any{
		"tid": tenantID,
		"amr": amr,
		"acr": "urn:hellojohn:loa:1",
		"scp": strings.Join(scopes, " "),
	}
	custom := map[string]any{}

	// Apply claims hook
	std, custom = s.deps.ClaimsHook.ApplyAccess(ctx, tenantID, clientID, userID, scopes, amr, std, custom)

	// Resolve effective issuer
	effIss := jwtx.ResolveIssuer(
		s.deps.Issuer.Iss,
		string(tda.Settings().IssuerMode),
		tenantSlug,
		tda.Settings().IssuerOverride,
	)

	// Add system claims
	custom = helpers.PutSystemClaimsV2(custom, effIss, nil, nil, nil)

	// Select signing key
	kid, priv, _, err := s.selectSigningKey(tda)
	if err != nil {
		log.Error("failed to get signing key", logger.Err(err))
		return nil, ErrRegisterTokenFailed
	}

	now := time.Now().UTC()
	exp := now.Add(s.deps.Issuer.AccessTTL)

	claims := jwtv5.MapClaims{
		"iss": effIss,
		"sub": userID,
		"aud": clientID,
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

	tk := jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, claims)
	tk.Header["kid"] = kid
	tk.Header["typ"] = "JWT"

	accessToken, err := tk.SignedString(priv)
	if err != nil {
		log.Error("failed to sign access token", logger.Err(err))
		return nil, fmt.Errorf("%w: %v", ErrRegisterTokenFailed, err)
	}

	// Generate refresh token
	rawRefresh, err := tokens.GenerateOpaqueToken(32)
	if err != nil {
		log.Error("failed to generate refresh token", logger.Err(err))
		return nil, fmt.Errorf("%w: %v", ErrRegisterTokenFailed, err)
	}

	refreshHash := tokens.SHA256Base64URL(rawRefresh)
	ttlSeconds := int(s.deps.RefreshTTL.Seconds())

	tokenInput := repository.CreateRefreshTokenInput{
		TenantID:   tenantID,
		ClientID:   clientID,
		UserID:     userID,
		TokenHash:  refreshHash,
		TTLSeconds: ttlSeconds,
	}

	if _, err := tda.Tokens().Create(ctx, tokenInput); err != nil {
		log.Error("failed to persist refresh token", logger.Err(err))
		return nil, fmt.Errorf("%w: %v", ErrRegisterTokenFailed, err)
	}

	log.Info("user registered with auto-login")

	return &dto.RegisterResult{
		UserID:       userID,
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		ExpiresIn:    int64(time.Until(exp).Seconds()),
	}, nil
}

// checkPasswordPolicy validates the password against configured policies.
func (s *registerService) checkPasswordPolicy(ctx context.Context, pwd, email, name string, policy *repository.SecurityPolicy) error {
	violations := passwordpolicy.Validate(pwd, policy, passwordpolicy.ValidationContext{
		Email:         email,
		Name:          name,
		BlacklistPath: s.deps.BlacklistPath,
	})
	if len(violations) > 0 {
		return fmt.Errorf("%w: %s", ErrRegisterPolicyViolation, violations[0].Message)
	}

	return nil
}

func (s *registerService) selectSigningKey(tda store.TenantDataAccess) (kid string, priv any, pub any, err error) {
	settings := tda.Settings()
	if types.IssuerMode(settings.IssuerMode) == types.IssuerModePath {
		return s.deps.Issuer.Keys.ActiveForTenant(tda.Slug())
	}
	return s.deps.Issuer.Keys.Active()
}
