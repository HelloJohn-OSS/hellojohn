package social

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	dtos "github.com/dropDatabas3/hellojohn/internal/http/dto/social"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
)

// CacheWriter extends Cache with write capabilities for callback service.
type CacheWriter interface {
	Get(key string) ([]byte, bool)
	Delete(key string) error
	Set(key string, value []byte, ttl time.Duration)
}

// CallbackDeps contains dependencies for callback service.
type CallbackDeps struct {
	StateSigner  StateSigner
	Cache        CacheWriter // Use CacheWriter for write capabilities
	LoginCodeTTL time.Duration
	Registry     *Registry           // Provider registry (replaces OIDCFactory)
	GenericOIDC  GenericOIDCResolver // Generic OIDC alias resolver
	Provisioning ProvisioningService // User provisioning service
	TokenService TokenService        // Token issuance service
	ClientConfig ClientConfigService // Client configuration validation
	AuditBus     *audit.AuditBus
}

// callbackService implements CallbackService.
type callbackService struct {
	stateSigner  StateSigner
	cache        CacheWriter
	loginCodeTTL time.Duration
	registry     *Registry
	genericOIDC  GenericOIDCResolver
	provisioning ProvisioningService
	tokenService TokenService
	clientConfig ClientConfigService
	auditBus     *audit.AuditBus
}

// NewCallbackService creates a new CallbackService.
func NewCallbackService(d CallbackDeps) CallbackService {
	ttl := d.LoginCodeTTL
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &callbackService{
		stateSigner:  d.StateSigner,
		cache:        d.Cache,
		loginCodeTTL: ttl,
		registry:     d.Registry,
		genericOIDC:  d.GenericOIDC,
		provisioning: d.Provisioning,
		tokenService: d.TokenService,
		clientConfig: d.ClientConfig,
		auditBus:     d.AuditBus,
	}
}

// Callback processes the OAuth callback.
func (s *callbackService) Callback(ctx context.Context, req CallbackRequest) (*CallbackResult, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Component("social.callback"))

	// Validate required fields
	if req.State == "" {
		return nil, ErrCallbackMissingState
	}
	if req.Code == "" {
		return nil, ErrCallbackMissingCode
	}

	// Parse and validate state
	if s.stateSigner == nil {
		log.Error("stateSigner not configured")
		return nil, ErrCallbackInvalidState
	}

	stateClaims, err := s.stateSigner.ParseState(req.State)
	if err != nil {
		log.Warn("state validation failed", logger.Err(err))
		return nil, fmt.Errorf("%w: %v", ErrCallbackInvalidState, err)
	}

	// Validate provider matches path
	if !strings.EqualFold(stateClaims.Provider, req.Provider) {
		log.Warn("provider mismatch",
			logger.String("path_provider", req.Provider),
			logger.String("state_provider", stateClaims.Provider),
		)
		s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "provider_mismatch")
		return nil, ErrCallbackProviderMismatch
	}

	// Validate required claims from state
	if stateClaims.TenantSlug == "" {
		log.Warn("state missing tenant_slug")
		return nil, ErrCallbackInvalidState
	}
	if stateClaims.ClientID == "" {
		log.Warn("state missing client_id")
		s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, "", "state_missing_client_id")
		return nil, ErrCallbackInvalidState
	}
	if stateClaims.Nonce == "" {
		log.Warn("state missing nonce")
		s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "state_missing_nonce")
		return nil, ErrCallbackInvalidState
	}

	if s.clientConfig == nil {
		log.Error("client configuration service not configured")
		s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "client_config_unavailable")
		return nil, ErrCallbackProviderDisabled
	}

	// Validate client exists.
	if _, err := s.clientConfig.GetClient(ctx, stateClaims.TenantSlug, stateClaims.ClientID); err != nil {
		if errors.Is(err, ErrClientNotFound) {
			log.Warn("client not found in control plane",
				logger.TenantID(stateClaims.TenantSlug),
			)
			s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "invalid_client")
			return nil, ErrCallbackInvalidClient
		}
		log.Error("failed to get client", logger.Err(err))
		s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "invalid_client")
		return nil, fmt.Errorf("%w: %v", ErrCallbackInvalidClient, err)
	}

	// Validate provider is allowed for this client.
	if err := s.clientConfig.IsProviderAllowed(ctx, stateClaims.TenantSlug, stateClaims.ClientID, req.Provider); err != nil {
		if errors.Is(err, ErrProviderMisconfigured) {
			log.Error("provider misconfigured", logger.Err(err))
			s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "provider_misconfigured")
			return nil, ErrCallbackProviderMisconfigured
		}
		if errors.Is(err, ErrSocialLoginDisabled) {
			log.Warn("social login disabled for tenant", logger.TenantID(stateClaims.TenantSlug))
			s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "social_login_disabled")
			return nil, ErrCallbackProviderDisabled
		}
		log.Warn("provider not allowed",
			logger.String("provider", req.Provider),
			logger.TenantID(stateClaims.TenantSlug),
			logger.Err(err),
		)
		s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "provider_not_allowed")
		return nil, ErrCallbackProviderDisabled
	}

	// Validate redirect_uri if present in state.
	if stateClaims.RedirectURI != "" {
		if err := s.clientConfig.ValidateRedirectURI(ctx, stateClaims.TenantSlug, stateClaims.ClientID, stateClaims.RedirectURI); err != nil {
			if errors.Is(err, ErrRedirectInvalid) || errors.Is(err, ErrRedirectNotAllowed) {
				log.Warn("redirect_uri validation failed",
					logger.Err(err),
				)
				s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "invalid_redirect_uri")
				return nil, ErrCallbackInvalidRedirect
			}
			log.Warn("redirect_uri validation error", logger.Err(err))
			s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "invalid_redirect_uri")
			return nil, ErrCallbackInvalidRedirect
		}
	}

	log.Info("callback validated",
		logger.String("provider", req.Provider),
		logger.TenantID(stateClaims.TenantSlug),
	)

	// Resolve provider client (registry + custom OIDC alias support).
	var (
		idClaims *OIDCClaims
		oidc     OIDCClient
	)
	if s.registry != nil && s.registry.Has(req.Provider) {
		oidc, err = s.registry.Build(ctx, req.Provider, stateClaims.TenantSlug, req.BaseURL)
		if err != nil {
			log.Error("failed to create OIDC client",
				logger.String("provider", req.Provider),
				logger.TenantID(stateClaims.TenantSlug),
				logger.Err(err),
			)
			s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "oidc_client_init_failed")
			return nil, fmt.Errorf("%w: %v", ErrCallbackOIDCExchangeFailed, err)
		}
	} else if s.genericOIDC != nil {
		oidc, err = s.genericOIDC.BuildForAlias(ctx, stateClaims.TenantSlug, req.BaseURL, req.Provider)
		if err != nil {
			log.Warn("generic OIDC alias resolution failed",
				logger.String("provider", req.Provider),
				logger.TenantID(stateClaims.TenantSlug),
				logger.Err(err),
			)
			s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "provider_unknown")
			return nil, ErrCallbackProviderUnknown
		}
	}

	if oidc == nil {
		log.Warn("provider not registered",
			logger.String("provider", req.Provider),
			logger.TenantID(stateClaims.TenantSlug),
		)
		s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "provider_unknown")
		return nil, ErrCallbackProviderUnknown
	}

	// Exchange authorization code for tokens.
	tokens, err := oidc.ExchangeCode(ctx, req.Code)
	if err != nil {
		log.Error("code exchange failed",
			logger.String("provider", req.Provider),
			logger.Err(err),
		)
		s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "code_exchange_failed")
		return nil, fmt.Errorf("%w: %v", ErrCallbackOIDCExchangeFailed, err)
	}

	// Verify ID token (or fetch user info for non-OIDC providers).
	verifyToken := strings.TrimSpace(tokens.IDToken)
	if providerUsesAccessTokenForVerification(req.Provider) {
		verifyToken = strings.TrimSpace(tokens.AccessToken)
	}
	if verifyToken == "" {
		// Fallback for providers that only return one token.
		if accessToken := strings.TrimSpace(tokens.AccessToken); accessToken != "" {
			verifyToken = accessToken
		}
	}

	idClaims, err = oidc.VerifyIDToken(ctx, verifyToken, stateClaims.Nonce)
	if err != nil {
		log.Error("ID token verification failed",
			logger.String("provider", req.Provider),
			logger.Err(err),
		)
		s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "id_token_invalid")
		return nil, fmt.Errorf("%w: %v", ErrCallbackIDTokenInvalid, err)
	}

	// Apple only sends user name fields once in callback form_post payload ("user").
	// Merge those fields into claims if present and not already populated by the ID token.
	if strings.EqualFold(req.Provider, "apple") && strings.TrimSpace(req.UserPayload) != "" {
		var payload struct {
			Name struct {
				FirstName string `json:"firstName"`
				LastName  string `json:"lastName"`
			} `json:"name"`
		}
		if err := json.Unmarshal([]byte(req.UserPayload), &payload); err != nil {
			log.Warn("invalid apple user payload", logger.Err(err))
		} else {
			firstName := strings.TrimSpace(payload.Name.FirstName)
			lastName := strings.TrimSpace(payload.Name.LastName)
			if idClaims.GivenName == "" {
				idClaims.GivenName = firstName
			}
			if idClaims.FamilyName == "" {
				idClaims.FamilyName = lastName
			}
			if idClaims.Name == "" {
				idClaims.Name = strings.TrimSpace(strings.TrimSpace(firstName + " " + lastName))
			}
		}
	}

	// Validate email is present
	if idClaims.Email == "" {
		log.Error("email missing from provider",
			logger.String("provider", req.Provider),
		)
		s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "email_missing")
		return nil, ErrCallbackEmailMissing
	}

	log.Info("OIDC exchange successful",
		logger.String("provider", req.Provider),
		logger.Bool("email_verified", idClaims.EmailVerified),
	)

	// Run user provisioning if we have claims and provisioning service
	var userID string
	if idClaims != nil && s.provisioning != nil {
		var err error
		userID, err = s.provisioning.EnsureUserAndIdentity(ctx, stateClaims.TenantSlug, req.Provider, idClaims)
		if err != nil {
			log.Error("user provisioning failed",
				logger.String("provider", req.Provider),
				logger.TenantID(stateClaims.TenantSlug),
				logger.Err(err),
			)
			s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "provisioning_failed")
			return nil, fmt.Errorf("%w: %v", ErrCallbackProvisionFailed, err)
		}

		log.Info("user provisioned",
			logger.String("provider", req.Provider),
			logger.TenantID(stateClaims.TenantSlug),
		)
	}

	// Issue real tokens using TokenService
	if s.tokenService == nil {
		log.Error("token service not configured",
			logger.String("provider", req.Provider),
			logger.TenantID(stateClaims.TenantSlug),
		)
		s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "token_service_not_configured")
		return nil, ErrCallbackTokenIssueFailed
	}
	if strings.TrimSpace(userID) == "" {
		log.Error("missing user_id for token issuance",
			logger.String("provider", req.Provider),
			logger.TenantID(stateClaims.TenantSlug),
		)
		s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "missing_user_id_for_token_issuance")
		return nil, ErrCallbackTokenIssueFailed
	}

	tokenResponse, err := s.tokenService.IssueSocialTokens(
		ctx,
		stateClaims.TenantSlug,
		stateClaims.ClientID,
		userID,
		[]string{req.Provider},
	)
	if err != nil {
		log.Error("token issuance failed",
			logger.String("provider", req.Provider),
			logger.TenantID(stateClaims.TenantSlug),
			logger.Err(err),
		)
		s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "token_issuance_failed")
		return nil, fmt.Errorf("%w: %v", ErrCallbackTokenIssueFailed, err)
	}

	auditTenantID := s.resolveAuditTenantID(ctx, stateClaims.TenantSlug)

	// Audit: social login success
	if s.auditBus != nil {
		s.auditBus.Emit(
			audit.NewEvent(audit.EventSocialLogin, auditTenantID).
				WithActor(userID, audit.ActorUser).
				WithTarget(userID, audit.TargetUser).
				WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx)).
				WithResult(audit.ResultSuccess).
				WithMeta("provider", req.Provider).
				WithMeta("client_id", stateClaims.ClientID),
		)
	}

	// If redirect_uri was provided, use login_code flow
	if stateClaims.RedirectURI != "" {
		// Generate login code
		loginCode, err := generateNonce(32)
		if err != nil {
			log.Error("failed to generate login code", logger.Err(err))
			s.emitSocialFailure(ctx, stateClaims.TenantSlug, req.Provider, stateClaims.ClientID, "login_code_generation_failed")
			return nil, ErrCallbackTokenIssueFailed
		}

		// Store payload in cache
		payload := dtos.ExchangePayload{
			ClientID:   stateClaims.ClientID,
			TenantID:   auditTenantID,
			TenantSlug: stateClaims.TenantSlug,
			Provider:   req.Provider,
			Response:   *tokenResponse,
		}
		payloadBytes, _ := json.Marshal(payload)

		cacheKey := "social:code:" + loginCode
		if s.cache != nil {
			s.cache.Set(cacheKey, payloadBytes, s.loginCodeTTL)
		}

		log.Info("login code stored",
			logger.TenantID(stateClaims.TenantSlug),
		)

		// Build redirect URL with code and social=true marker
		redirectURL := stateClaims.RedirectURI
		if u, err := url.Parse(redirectURL); err == nil {
			q := u.Query()
			q.Set("code", loginCode)
			q.Set("social", "true") // Marker for SDK to identify social login callback
			u.RawQuery = q.Encode()
			redirectURL = u.String()
		} else {
			sep := "?"
			if strings.Contains(redirectURL, "?") {
				sep = "&"
			}
			redirectURL = redirectURL + sep + "code=" + loginCode + "&social=true"
		}

		return &CallbackResult{
			RedirectURL: redirectURL,
		}, nil
	}

	// Direct JSON response (no redirect)
	respBytes, _ := json.Marshal(tokenResponse)
	return &CallbackResult{
		JSONResponse: respBytes,
	}, nil
}

// resolveAuditTenantID extrae el UUID del tenant desde el TDA en contexto.
// El TenantMiddleware inyecta el TDA antes de que llegue al servicio.
// Si no hay TDA disponible, retorna el ID del control plane.
func (s *callbackService) resolveAuditTenantID(ctx context.Context, _ string) string {
	if tda := mw.GetTenant(ctx); tda != nil {
		if id := strings.TrimSpace(tda.ID()); id != "" {
			return id
		}
	}
	return audit.ControlPlaneTenantID
}

// emitSocialFailure emits a social login failure audit event.
func (s *callbackService) emitSocialFailure(ctx context.Context, tenantSlug, provider, clientID, reason string) {
	if s.auditBus == nil {
		return
	}

	tenantID := s.resolveAuditTenantID(ctx, tenantSlug)
	evt := audit.NewEvent(audit.EventLoginFailed, tenantID).
		WithActor("", audit.ActorSystem).
		WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx)).
		WithResult(audit.ResultFailure).
		WithMeta("provider", provider).
		WithMeta("reason", reason)
	if strings.TrimSpace(clientID) != "" {
		evt = evt.WithMeta("client_id", clientID)
	}
	if strings.TrimSpace(tenantSlug) != "" && !strings.EqualFold(strings.TrimSpace(tenantSlug), tenantID) {
		evt = evt.WithMeta("tenant_slug", strings.TrimSpace(tenantSlug))
	}

	s.auditBus.Emit(evt)
}

func providerUsesAccessTokenForVerification(provider string) bool {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "google", "apple":
		return false
	default:
		return true
	}
}
