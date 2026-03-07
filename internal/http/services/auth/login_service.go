package auth

import (
	"context"
	"encoding/json"
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
	adaptive "github.com/dropDatabas3/hellojohn/internal/mfa/adaptive"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	bot "github.com/dropDatabas3/hellojohn/internal/http/services/bot"
)

// LoginDeps contiene las dependencias para el login service.
type LoginDeps struct {
	DAL                  store.DataAccessLayer
	Issuer               *jwtx.Issuer
	RefreshTTL           time.Duration
	ClaimsHook           ClaimsHook // nil = NoOp
	PhoneField           string
	PreferredFactorField string
	SMSGlobalAvailable   bool
	AdaptiveConfig       adaptive.Config
	AdaptiveEngine       *adaptive.Engine
	AuditBus             *audit.AuditBus
	// BotProtection valida tokens anti-bot antes de procesar credenciales.
	// Si nil, se omite la validación (equivalente a NoopService).
	BotProtection bot.BotProtectionService
}

type loginService struct {
	deps LoginDeps
}

// NewLoginService crea un nuevo servicio de login.
func NewLoginService(deps LoginDeps) LoginService {
	if deps.ClaimsHook == nil {
		deps.ClaimsHook = NoOpClaimsHook{}
	}
	deps.PhoneField = strings.TrimSpace(deps.PhoneField)
	if deps.PhoneField == "" {
		deps.PhoneField = "phone"
	}
	deps.PreferredFactorField = strings.TrimSpace(deps.PreferredFactorField)
	if deps.PreferredFactorField == "" {
		deps.PreferredFactorField = defaultMFAPreferredFactorField
	}
	deps.AdaptiveConfig = deps.AdaptiveConfig.Normalize()
	if deps.AdaptiveEngine == nil {
		deps.AdaptiveEngine = adaptive.NewEngine()
	}
	return &loginService{deps: deps}
}

// Errores de login
var (
	ErrMissingFields      = fmt.Errorf("missing required fields")
	ErrInvalidClient      = fmt.Errorf("invalid client")
	ErrPasswordNotAllowed = fmt.Errorf("password login not allowed for this client")
	ErrInvalidCredentials = fmt.Errorf("invalid credentials")
	ErrUserDisabled       = fmt.Errorf("user disabled")
	ErrEmailNotVerified   = fmt.Errorf("email not verified")
	ErrNoDatabase         = fmt.Errorf("no database for tenant")
	ErrTokenIssueFailed   = fmt.Errorf("failed to issue token")
)

func (s *loginService) LoginPassword(ctx context.Context, in dto.LoginRequest) (*dto.LoginResult, error) {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component("auth.login"),
		logger.Op("LoginPassword"),
	)

	// Paso 0: Bot protection — validar antes de procesar credenciales
	if s.deps.BotProtection != nil {
		if err := s.deps.BotProtection.Validate(ctx, bot.ValidateRequest{
			Token:      in.TurnstileToken,
			RemoteIP:   in.RemoteIP,
			TenantSlug: in.TenantID,
			Endpoint:   "login",
		}); err != nil {
			switch {
			case errors.Is(err, bot.ErrTokenMissing):
				return nil, httperrors.ErrBotTokenMissing
			default:
				return nil, httperrors.ErrBotVerificationFailed
			}
		}
	}

	// Paso 1: Normalización
	in.Email = strings.TrimSpace(strings.ToLower(in.Email))
	in.TenantID = strings.TrimSpace(in.TenantID)
	in.ClientID = strings.TrimSpace(in.ClientID)

	// Validación: email y password siempre requeridos
	if in.Email == "" || in.Password == "" {
		return nil, ErrMissingFields
	}

	// Si faltan tenant_id y/o client_id, intentar login como admin global
	if in.TenantID == "" || in.ClientID == "" {
		return s.loginAsAdmin(ctx, in, log)
	}

	// Paso 1: Resolver tenant (sin abrir DB todavía)
	tda, err := s.deps.DAL.ForTenant(ctx, in.TenantID)
	if err != nil {
		log.Debug("tenant resolution failed", logger.Err(err))
		return nil, ErrInvalidClient
	}
	tenantSlug := tda.Slug()
	tenantID := tda.ID()
	effectiveAdaptiveCfg := resolveAdaptiveConfigForTenant(s.deps.AdaptiveConfig, tda.Settings())

	log = log.With(logger.TenantSlug(tenantSlug))

	// Paso 2: Resolver client por FS y aplicar provider gating
	client, err := tda.Clients().Get(ctx, in.ClientID)
	if err != nil {
		log.Debug("client not found", logger.Err(err))
		return nil, ErrInvalidClient
	}

	// Provider gating: verificar que "password" esté permitido
	if !helpers.IsPasswordProviderAllowed(client.Providers) {
		log.Debug("password provider not allowed")
		return nil, ErrPasswordNotAllowed
	}

	// Paso 3: Ahora sí requerir DB
	if err := tda.RequireDB(); err != nil {
		log.Debug("tenant DB not available", logger.Err(err))
		return nil, ErrNoDatabase
	}

	// Paso 4: Buscar usuario y verificar password
	// Claims Defaults (Hoist to fix scope)
	amr := []string{"pwd"}
	acr := "urn:hellojohn:loa:1"

	user, identity, err := tda.Users().GetByEmail(ctx, tenantID, in.Email)
	if err != nil {
		log.Debug("user not found")
		// Audit: login failed - user not found
		if s.deps.AuditBus != nil {
			s.deps.AuditBus.Emit(
				audit.NewEvent(audit.EventLoginFailed, tenantID).
					WithActor("", audit.ActorUser).
					WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx)).
					WithResult(audit.ResultFailure).
					WithMeta("reason", "user_not_found").
					WithMeta("client_id", in.ClientID),
			)
		}
		return nil, ErrInvalidCredentials
	}

	log = log.With(logger.UserID(user.ID))

	// Verificar estado del usuario
	if helpers.IsUserDisabled(user) {
		log.Info("user disabled")
		// Audit: login failed - user disabled
		if s.deps.AuditBus != nil {
			s.deps.AuditBus.Emit(
				audit.NewEvent(audit.EventLoginFailed, tenantID).
					WithActor(user.ID, audit.ActorUser).
					WithTarget(user.ID, audit.TargetUser).
					WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx)).
					WithResult(audit.ResultFailure).
					WithMeta("reason", "user_disabled").
					WithMeta("client_id", in.ClientID),
			)
		}
		return nil, ErrUserDisabled
	}

	// Verificar password
	if identity == nil || identity.PasswordHash == nil || *identity.PasswordHash == "" {
		log.Debug("no password identity")
		return nil, ErrInvalidCredentials
	}

	if !tda.Users().CheckPassword(identity.PasswordHash, in.Password) {
		log.Debug("password check failed")
		if effectiveAdaptiveCfg.Enabled {
			if _, incErr := adaptive.IncrementFail(ctx, tda.Cache(), tenantID, user.ID, effectiveAdaptiveCfg.StateTTL); incErr != nil {
				log.Warn("adaptive fail counter increment failed", logger.Err(incErr))
			}
		}
		// Audit: login failed - wrong password
		if s.deps.AuditBus != nil {
			s.deps.AuditBus.Emit(
				audit.NewEvent(audit.EventLoginFailed, tenantID).
					WithActor(user.ID, audit.ActorUser).
					WithTarget(user.ID, audit.TargetUser).
					WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx)).
					WithResult(audit.ResultFailure).
					WithMeta("reason", "invalid_password").
					WithMeta("client_id", in.ClientID),
			)
		}
		return nil, ErrInvalidCredentials
	}

	// Paso 5: Email verification gating
	if client.RequireEmailVerification && !user.EmailVerified {
		log.Info("email not verified")
		return nil, ErrEmailNotVerified
	}

	// Paso 6: MFA gate (base + adaptive)
	availableFactors, preferredFactor, hasConfirmedTOTP, factorErr := collectAvailableMFAFactors(
		ctx,
		tda,
		user,
		s.deps.PhoneField,
		s.deps.PreferredFactorField,
		s.deps.SMSGlobalAvailable,
	)
	if factorErr != nil {
		log.Warn("failed to collect mfa factors", logger.Err(factorErr))
	}
	if hasConfirmedTOTP && !containsFactor(availableFactors, mfaFactorTOTP) {
		availableFactors = append([]string{mfaFactorTOTP}, availableFactors...)
	}
	if preferredFactor == "" {
		preferredFactor = fallbackPreferredFactor(availableFactors)
	}

	isTrusted := false
	if hasConfirmedTOTP {
		if mfaRepo := tda.MFA(); mfaRepo != nil && in.TrustedDeviceToken != "" {
			deviceHash := tokens.SHA256Base64URL(in.TrustedDeviceToken)
			trusted, tdErr := mfaRepo.IsTrustedDevice(ctx, user.ID, deviceHash)
			if tdErr != nil {
				log.Warn("trusted device check failed", logger.Err(tdErr))
			}
			isTrusted = trusted
		}
	}
	mustChallenge := hasConfirmedTOTP && !isTrusted
	if effectiveAdaptiveCfg.Enabled {
		state, stErr := adaptive.LoadState(ctx, tda.Cache(), tenantID, user.ID)
		if stErr != nil {
			log.Warn("adaptive state load failed", logger.Err(stErr))
		} else {
			decision := s.deps.AdaptiveEngine.Evaluate(adaptive.Context{
				TenantID:       tenantID,
				UserID:         user.ID,
				CurrentIP:      mw.GetClientIP(ctx),
				CurrentUA:      mw.GetUserAgent(ctx),
				LastIP:         state.LastIP,
				LastUA:         state.LastUA,
				FailedAttempts: state.FailedAttempts,
				Now:            time.Now().UTC(),
			}, effectiveAdaptiveCfg)
			if decision.RequireMFA {
				if len(availableFactors) > 0 {
					mustChallenge = true
					log.Warn("adaptive rule triggered mfa challenge",
						logger.String("rule", decision.Rule),
						logger.String("reason", decision.Reason),
					)
				} else {
					log.Warn("adaptive rule triggered but no factor available (fail-open)",
						logger.String("rule", decision.Rule),
						logger.String("reason", decision.Reason),
					)
					if s.deps.AuditBus != nil {
						s.deps.AuditBus.Emit(
							audit.NewEvent(audit.EventLogin, tenantID).
								WithActor(user.ID, audit.ActorUser).
								WithTarget(user.ID, audit.TargetUser).
								WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx)).
								WithMeta("client_id", in.ClientID).
								WithMeta("method", "password").
								WithMeta("reason", "adaptive_triggered_without_factor").
								WithMeta("rule", decision.Rule),
						)
					}
				}
			}
		}
	}

	if mustChallenge && len(availableFactors) > 0 {
		// Create challenge token for MFA step-up.
		mfaToken, err := tokens.GenerateOpaqueToken(32)
		if err != nil {
			log.Error("failed to generate mfa token", logger.Err(err))
			return nil, ErrTokenIssueFailed
		}

		challenge := map[string]any{
			"uid": user.ID,
			"tid": tenantID,
			"cid": in.ClientID,
			"amr": []string{"pwd"},
			"scp": client.Scopes,
		}
		challengeJSON, _ := json.Marshal(challenge)
		cacheKey := "mfa:token:" + mfaToken
		if err := tda.Cache().Set(ctx, cacheKey, string(challengeJSON), 5*time.Minute); err != nil {
			log.Error("failed to cache mfa challenge", logger.Err(err))
			return nil, ErrTokenIssueFailed
		}

		return &dto.LoginResult{
			MFARequired:      true,
			MFAToken:         mfaToken,
			AMR:              []string{"pwd"},
			AvailableFactors: availableFactors,
			PreferredFactor:  preferredFactor,
		}, nil
	}

	// Trusted-device bypass only applies when adaptive did not force challenge.
	if hasConfirmedTOTP && isTrusted && !mustChallenge {
		amr = append(amr, "mfa")
		acr = "urn:hellojohn:loa:2"
	}

	// Paso 7: Claims base
	// Paso 7: Claims base
	grantedScopes := client.Scopes

	std := map[string]any{
		"tid": tenantID,
		"amr": amr,
		"acr": acr,
		"scp": strings.Join(grantedScopes, " "),
	}
	custom := map[string]any{}

	// RBAC (TODO en iteración 2): roles/perms si disponibles

	// Claims hook (extensible)
	std, custom = s.deps.ClaimsHook.ApplyAccess(ctx, tenantID, in.ClientID, user.ID, grantedScopes, amr, std, custom)

	// Paso 8: Resolver issuer efectivo y emitir Access Token
	effIss := jwtx.ResolveIssuer(
		s.deps.Issuer.Iss,
		string(tda.Settings().IssuerMode),
		tenantSlug,
		tda.Settings().IssuerOverride,
	)

	now := time.Now().UTC()
	exp := now.Add(s.deps.Issuer.AccessTTL)

	// Seleccionar key según modo
	kid, priv, _, err := s.selectSigningKey(tda)
	if err != nil {
		log.Error("failed to get signing key", logger.Err(err))
		return nil, ErrTokenIssueFailed
	}

	claims := jwtv5.MapClaims{
		"iss": effIss,
		"sub": user.ID,
		"aud": in.ClientID,
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
		return nil, ErrTokenIssueFailed
	}

	// Paso 9: Refresh token persistente
	rawRefresh, err := tokens.GenerateOpaqueToken(32)
	if err != nil {
		log.Error("failed to generate refresh token", logger.Err(err))
		return nil, ErrTokenIssueFailed
	}

	// Guardar refresh token hash en DB
	refreshHash := tokens.SHA256Base64URL(rawRefresh)
	ttlSeconds := int(s.deps.RefreshTTL.Seconds())

	tokenInput := repository.CreateRefreshTokenInput{
		TenantID:   tenantID,
		ClientID:   in.ClientID,
		UserID:     user.ID,
		TokenHash:  refreshHash,
		TTLSeconds: ttlSeconds,
	}

	if _, err := tda.Tokens().Create(ctx, tokenInput); err != nil {
		log.Error("failed to persist refresh token", logger.Err(err))
		return nil, ErrTokenIssueFailed
	}

	if effectiveAdaptiveCfg.Enabled {
		if err := adaptive.SaveSuccessState(
			ctx,
			tda.Cache(),
			tenantID,
			user.ID,
			mw.GetClientIP(ctx),
			mw.GetUserAgent(ctx),
			effectiveAdaptiveCfg.StateTTL,
		); err != nil {
			log.Warn("failed to persist adaptive success state", logger.Err(err))
		}
	}

	log.Info("login successful")

	// Audit: login exitoso
	if s.deps.AuditBus != nil {
		s.deps.AuditBus.Emit(
			audit.NewEvent(audit.EventLogin, tenantID).
				WithActor(user.ID, audit.ActorUser).
				WithTarget(user.ID, audit.TargetUser).
				WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx)).
				WithMeta("client_id", in.ClientID).
				WithMeta("method", "password"),
		)
	}

	return &dto.LoginResult{
		Success:      true,
		AccessToken:  accessToken,
		RefreshToken: rawRefresh,
		ExpiresIn:    int64(time.Until(exp).Seconds()),
	}, nil
}

// ─── Internal Helpers ───
// Nota: helpers comunes están en internal/http/v2/helpers/

func (s *loginService) selectSigningKey(tda store.TenantDataAccess) (kid string, priv any, pub any, err error) {
	settings := tda.Settings()
	if types.IssuerMode(settings.IssuerMode) == types.IssuerModePath {
		return s.deps.Issuer.Keys.ActiveForTenant(tda.Slug())
	}
	return s.deps.Issuer.Keys.Active()
}

// loginAsAdmin maneja el login de administradores globales del sistema.
// Se usa cuando tenant_id y/o client_id están vacíos.
func (s *loginService) loginAsAdmin(ctx context.Context, in dto.LoginRequest, log *zap.Logger) (*dto.LoginResult, error) {
	log = log.With(logger.Op("loginAsAdmin"))

	// Obtener el AdminRepository del Control Plane
	adminRepo := s.deps.DAL.ConfigAccess().Admins()
	if adminRepo == nil {
		log.Debug("admin repository not available")
		return nil, ErrInvalidCredentials
	}

	// Buscar admin por email
	admin, err := adminRepo.GetByEmail(ctx, in.Email)
	if err != nil {
		log.Debug("admin not found", logger.Err(err))
		return nil, ErrInvalidCredentials
	}

	// Verificar que no esté deshabilitado
	if admin.DisabledAt != nil {
		log.Info("admin disabled")
		return nil, ErrUserDisabled
	}

	// Verificar password
	if !adminRepo.CheckPassword(admin.PasswordHash, in.Password) {
		log.Debug("admin password check failed")
		return nil, ErrInvalidCredentials
	}

	// Actualizar last seen (best effort)
	_ = adminRepo.UpdateLastSeen(ctx, admin.ID)

	// 4. Emitir access token usando el Issuer estándar de admin
	// Esto asegura que aud="hellojohn:admin" y admin_type estén en el nivel superior
	accessToken, expiresIn, err := s.deps.Issuer.IssueAdminAccess(ctx, jwtx.AdminAccessClaims{
		AdminID:   admin.ID,
		Email:     admin.Email,
		AdminType: string(admin.Type),
		Tenants:   buildTenantClaims(admin.TenantAccess),
		Perms:     jwtx.DefaultAdminPerms(string(admin.Type)),
	})
	if err != nil {
		log.Error("failed to issue access token", logger.Err(err))
		return nil, ErrTokenIssueFailed
	}

	// Recalcular expiración para el response (IssueAdminAccess devuelve duración en segundos)
	// Nota: `expiresIn` ya es int segundos.
	// exp para refresh token:
	refreshExp := time.Now().Add(s.deps.RefreshTTL)

	// Para admins vía loginAsAdmin, emitir refresh token como JWT stateless
	// Obtener clave de firma global (requerida para firmar el refresh token manualmente)
	kid, priv, _, kerr := s.deps.Issuer.Keys.Active()
	if kerr != nil {
		log.Error("failed to get signing key", logger.Err(kerr))
		return nil, ErrTokenIssueFailed
	}

	// Importante: aud debe coincidir con lo esperado si se verificara, o al menos no ser "admin" genérico si causa conflictos.
	// Por consistencia usamos "hellojohn:admin"
	rtClaims := jwtv5.MapClaims{
		"iss":       s.deps.Issuer.Iss,
		"sub":       admin.ID,
		"aud":       "hellojohn:admin",
		"iat":       time.Now().Unix(),
		"nbf":       time.Now().Unix(),
		"exp":       refreshExp.Unix(),
		"token_use": "refresh",
	}
	rtToken := jwtv5.NewWithClaims(jwtv5.SigningMethodEdDSA, rtClaims)
	rtToken.Header["kid"] = kid
	rtToken.Header["typ"] = "JWT"

	refreshToken, err := rtToken.SignedString(priv)
	if err != nil {
		log.Error("failed to sign refresh token", logger.Err(err))
		return nil, ErrTokenIssueFailed
	}

	log.Info("admin login successful (via loginAsAdmin)")

	// Audit: admin login exitoso
	if s.deps.AuditBus != nil {
		s.deps.AuditBus.Emit(
			audit.NewEvent(audit.EventLogin, audit.ControlPlaneTenantID).
				WithActor(admin.ID, audit.ActorAdmin).
				WithTarget(admin.ID, audit.TargetUser).
				WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx)).
				WithMeta("method", "password").
				WithMeta("admin_type", string(admin.Type)),
		)
	}

	return &dto.LoginResult{
		Success:      true,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(expiresIn),
	}, nil
}

func resolveAdaptiveConfigForTenant(global adaptive.Config, settings *repository.TenantSettings) adaptive.Config {
	cfg := global.Normalize()
	if settings == nil || settings.MFA == nil || settings.MFA.Adaptive == nil {
		return cfg
	}

	tenantAdaptive := settings.MFA.Adaptive
	if tenantAdaptive.Enabled != nil {
		cfg.Enabled = *tenantAdaptive.Enabled
	}
	if len(tenantAdaptive.Rules) > 0 {
		cfg.Rules = tenantAdaptive.Rules
	}
	if tenantAdaptive.FailureThreshold > 0 {
		cfg.FailureThreshold = tenantAdaptive.FailureThreshold
	}
	if tenantAdaptive.StateTTLHours > 0 {
		cfg.StateTTL = time.Duration(tenantAdaptive.StateTTLHours) * time.Hour
	}
	return cfg.Normalize()
}

// buildTenantClaims convierte []repository.TenantAccessEntry a []jwtx.TenantAccessClaim.
func buildTenantClaims(entries []repository.TenantAccessEntry) []jwtx.TenantAccessClaim {
	if len(entries) == 0 {
		return nil
	}
	out := make([]jwtx.TenantAccessClaim, 0, len(entries))
	for _, e := range entries {
		role := e.Role
		if role == "" {
			role = "member"
		}
		out = append(out, jwtx.TenantAccessClaim{Slug: e.TenantSlug, Role: role})
	}
	return out
}
