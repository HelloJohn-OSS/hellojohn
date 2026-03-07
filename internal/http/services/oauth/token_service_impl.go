package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/claims"
	"github.com/dropDatabas3/hellojohn/internal/claims/resolver"
	controlplane "github.com/dropDatabas3/hellojohn/internal/controlplane"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// TokenDeps contains dependencies for token service.
type TokenDeps struct {
	DAL                          store.DataAccessLayer
	Issuer                       *jwtx.Issuer
	Cache                        CacheClient
	ControlPlane                 controlplane.Service
	RefreshTTL                   time.Duration
	ClientProfilesEnabled        bool
	RefreshReuseDetectionEnabled bool
}

// tokenService implements TokenService.
type tokenService struct {
	dal                          store.DataAccessLayer
	issuer                       *jwtx.Issuer
	cache                        CacheClient
	cp                           controlplane.Service
	refreshTTL                   time.Duration
	clientProfilesEnabled        bool
	refreshReuseDetectionEnabled bool
}

// NewTokenService creates a new TokenService.
func NewTokenService(d TokenDeps) TokenService {
	ttl := d.RefreshTTL
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour // 30 days default
	}
	return &tokenService{
		dal:                          d.DAL,
		issuer:                       d.Issuer,
		cache:                        d.Cache,
		cp:                           d.ControlPlane,
		refreshTTL:                   ttl,
		clientProfilesEnabled:        d.ClientProfilesEnabled,
		refreshReuseDetectionEnabled: d.RefreshReuseDetectionEnabled,
	}
}

// ExchangeAuthorizationCode handles grant_type=authorization_code (PKCE).
func (s *tokenService) ExchangeAuthorizationCode(ctx context.Context, req AuthCodeRequest) (*TokenResponse, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Op("oauth.token.authcode"))

	// Validate required fields
	if req.Code == "" || req.RedirectURI == "" || req.ClientID == "" || req.CodeVerifier == "" {
		return nil, ErrTokenInvalidRequest
	}

	// Lookup client from control plane
	client, tenantSlug, err := s.lookupClient(ctx, req.TenantSlug, req.ClientID)
	if err != nil {
		log.Warn("client not found", logger.String("client_id", req.ClientID), logger.Err(err))
		return nil, ErrTokenInvalidClient
	}

	// Validate grant_type is allowed for this client
	if !isGrantTypeAllowed(client, "authorization_code", s.clientProfilesEnabled) {
		log.Warn("grant_type not allowed for client", logger.String("grant_type", "authorization_code"))
		return nil, ErrTokenUnsupportedGrantType
	}

	// Consume authorization code from cache (one-shot)
	// Hardening: check for hashed code first
	codeHash := tokens.SHA256Base64URL(req.Code)
	keyHashed := "code:" + codeHash
	keyPlain := "code:" + req.Code

	key := keyHashed
	data, ok := s.cache.Get(keyHashed)
	if !ok {
		// Fallback: check plain code (legacy/transient)
		key = keyPlain
		data, ok = s.cache.Get(keyPlain)
	}

	if !ok {
		log.Warn("authorization code not found")
		return nil, ErrTokenInvalidGrant
	}
	s.cache.Delete(key)

	var ac AuthCodePayload
	if err := json.Unmarshal(data, &ac); err != nil {
		log.Warn("authorization code corrupted", logger.Err(err))
		return nil, ErrTokenInvalidGrant
	}

	// Validate authorization code
	if time.Now().After(ac.ExpiresAt) {
		log.Warn("authorization code expired")
		return nil, ErrTokenInvalidGrant
	}
	if ac.ClientID != client.ClientID || ac.RedirectURI != req.RedirectURI {
		log.Warn("client/redirect_uri mismatch")
		return nil, ErrTokenInvalidGrant
	}

	// Validate PKCE S256
	verifierHash := tokens.SHA256Base64URL(req.CodeVerifier)
	if !strings.EqualFold(ac.ChallengeMethod, "S256") || !strings.EqualFold(ac.CodeChallenge, verifierHash) {
		log.Warn("PKCE verification failed")
		return nil, ErrTokenInvalidGrant
	}

	// Build access token claims
	reqScopes := strings.Fields(ac.Scope)
	acrVal := "urn:hellojohn:loa:1"
	for _, v := range ac.AMR {
		if v == "mfa" {
			acrVal = "urn:hellojohn:loa:2"
			break
		}
	}

	std := map[string]any{
		"tid":   tenantSlug,
		"amr":   ac.AMR,
		"acr":   acrVal,
		"scope": strings.Join(reqScopes, " "),
		"scp":   reqScopes,
	}
	custom := map[string]any{}

	// --- PHASE 6.4/6.5 OIDC CUSTOM CLAIMS RESOLUTION ---
	// Recuperamos del Tenant los Custom Claims Habilitados
	if tenantData, err := s.dal.ForTenant(ctx, tenantSlug); err == nil {
		// Preparamos el CEL Engine estático (Singleton)
		celEng, _ := resolver.NewCELEngine()

		var hookConfigs []claims.ClaimConfig
		resolversMap := map[string]resolver.Resolver{
			"static":         &resolver.StaticResolver{},
			"user_attribute": &resolver.UserAttributeResolver{},
		}

		claimsDefinitions, err := tenantData.Claims().List(ctx)
		if err == nil {
			for _, def := range claimsDefinitions {
				if def.Enabled {
					conf := claims.ClaimConfig{
						ClaimName:    def.Name,
						ResolverType: def.Source,
						Required:     def.Required,
						Scopes:       def.Scopes,
						ConfigData:   def.ConfigData,
					}
					hookConfigs = append(hookConfigs, conf)

					// Instanciación "On The Fly" o "Load-Time" acoplado al Request-Time
					if def.Source == "expression" {
						exprStr, ok := def.ConfigData["expression"].(string)
						if ok && exprStr != "" {
							prog, err := celEng.Compile(exprStr)
							if err == nil {
								// Prefijamos el claim id para no colisionar con otros CELs
								resolversMap[def.Name] = resolver.NewExpressionResolver(prog)
								conf.ResolverType = def.Name // Redireccionamos el resolver al key customizado
								hookConfigs[len(hookConfigs)-1] = conf
							} else {
								log.Warn("cel expression compile failed in jwt pre-flight", logger.String("claim", def.Name), logger.Err(err))
							}
						}
					} else if def.Source == "webhook_api" {
						urlStr, _ := def.ConfigData["url"].(string)
						var encSecret string
						// El secret en Base de Datos para Webhooks se llama 'secret_enc'
						if s, ok := def.ConfigData["secret_enc"].(string); ok {
							encSecret = s
						} else {
							// Dummy secret si viene vacío (Fallback legacy)
							encSecret = "dummy"
						}

						headersMap := map[string]string{}
						if hds, ok := def.ConfigData["headers"].(map[string]any); ok {
							for hk, hv := range hds {
								if hs, isStr := hv.(string); isStr {
									headersMap[hk] = hs
								}
							}
						}

						// 2 segundos hard-limit
						w, err := resolver.NewWebhookResolver(urlStr, encSecret, 2*time.Second, headersMap)
						if err == nil {
							resolversMap[def.Name] = w
							conf.ResolverType = def.Name // Redirigimos al key instanciado
							hookConfigs[len(hookConfigs)-1] = conf
						} else {
							log.Warn("webhook api resolver compile failed", logger.String("claim", def.Name), logger.Err(err))
						}
					}
				}
			}

			// User Lookup para inyección de perfiles a resolver
			var userEmail string
			var userMeta map[string]any
			if user, err := tenantData.Users().GetByID(ctx, ac.UserID); err == nil && user != nil {
				userEmail = user.Email
				userMeta = user.Metadata
			}

			hook := claims.NewClaimsHook(hookConfigs, resolversMap)
			resolverIn := resolver.ResolverInput{
				UserID:   ac.UserID,
				TenantID: tenantSlug,
				Email:    userEmail,
				Scopes:   reqScopes,
				ClientID: req.ClientID,
				UserMeta: userMeta,
			}

			// Ejecución Concurrente/Secuencial con Fail-Closed Mitigation
			if resolvedClaims, err := hook.ResolveAll(ctx, resolverIn); err != nil {
				log.Error("jwt payload aborted due to critical resolution failure", logger.Err(err))
				return nil, ErrTokenServerError // Fail Closed: Manda HTTP 500 al User si un 'Required=true' explotó.
			} else {
				// Hacemos merge del resultado dinámico sobre el Custom base
				for k, v := range resolvedClaims {
					custom[k] = v
				}
			}
		} // Cierre if claimsDefinitions err == nil
	}
	// ----------------------------------------------------

	// Resolve effective issuer for tenant
	effIss := s.resolveEffectiveIssuer(ctx, tenantSlug)
	accessTTLSeconds := s.effectiveAccessTTLSeconds(ctx, tenantSlug, client.AccessTokenTTL)
	refreshTTLSeconds := s.effectiveRefreshTTLSeconds(ctx, tenantSlug, client.RefreshTokenTTL)

	// Issue access token with client-specific TTL (if configured)
	access, exp, err := s.issuer.IssueAccessForTenantWithTTL(tenantSlug, effIss, ac.UserID, req.ClientID, std, custom, accessTTLSeconds)
	if err != nil {
		log.Error("failed to issue access token", logger.Err(err))
		return nil, ErrTokenServerError
	}

	// Create refresh token with client-specific TTL
	rawRT, err := s.createRefreshTokenWithTTL(ctx, tenantSlug, client.ClientID, ac.UserID, refreshTTLSeconds, nil)
	if err != nil {
		log.Error("failed to create refresh token", logger.Err(err))
		return nil, ErrTokenServerError
	}

	// Issue ID token with client-specific TTL (if configured)
	idStd := map[string]any{
		"tid":     tenantSlug,
		"at_hash": atHash(access),
		"azp":     req.ClientID,
		"acr":     acrVal,
		"amr":     ac.AMR,
	}
	idExtra := map[string]any{}
	if ac.Nonce != "" {
		idExtra["nonce"] = ac.Nonce
	}

	// Enrich ID token with claims based on granted scopes
	if tenantData, err := s.dal.ForTenant(ctx, tenantSlug); err == nil {
		if user, err := tenantData.Users().GetByID(ctx, ac.UserID); err == nil {
			s.enrichClaimsFromScopes(ctx, idExtra, tenantSlug, user, reqScopes)
		}
	}

	idTTLSeconds := resolveEffectiveTTLSeconds(client.IDTokenTTL, 0, s.issuer.AccessTTL)
	idToken, _, err := s.issuer.IssueIDTokenForTenantWithTTL(tenantSlug, effIss, ac.UserID, req.ClientID, idStd, idExtra, idTTLSeconds)
	if err != nil {
		log.Error("failed to issue id_token", logger.Err(err))
		return nil, ErrTokenServerError
	}

	log.Info("authorization_code exchanged",
		logger.TenantID(tenantSlug),
		logger.String("client_id", req.ClientID),
	)

	return &TokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int64(time.Until(exp).Seconds()),
		RefreshToken: rawRT,
		IDToken:      idToken,
		Scope:        ac.Scope,
	}, nil
}

// ExchangeRefreshToken handles grant_type=refresh_token (rotation).
func (s *tokenService) ExchangeRefreshToken(ctx context.Context, req RefreshTokenRequest) (*TokenResponse, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Op("oauth.token.refresh"))

	if req.ClientID == "" || req.RefreshToken == "" {
		return nil, ErrTokenInvalidRequest
	}

	// Lookup client
	client, tenantSlug, err := s.lookupClient(ctx, req.TenantSlug, req.ClientID)
	if err != nil {
		log.Warn("client not found", logger.String("client_id", req.ClientID))
		return nil, ErrTokenInvalidClient
	}

	// Validate grant_type is allowed for this client
	if !isGrantTypeAllowed(client, "refresh_token", s.clientProfilesEnabled) {
		log.Warn("grant_type not allowed for client", logger.String("grant_type", "refresh_token"))
		return nil, ErrTokenUnsupportedGrantType
	}

	// Get tenant data access
	tenantData, err := s.dal.ForTenant(ctx, tenantSlug)
	if err != nil {
		log.Warn("tenant data access not available", logger.TenantID(tenantSlug))
		return nil, ErrTokenDBNotConfigured
	}

	// Lookup refresh token by hash
	tokenHash := tokens.SHA256Base64URL(req.RefreshToken)
	rt, err := tenantData.Tokens().GetByHash(ctx, tokenHash)
	if err != nil {
		log.Warn("refresh token not found or invalid")
		return nil, ErrTokenInvalidGrant
	}

	// Validate refresh token
	now := time.Now()
	// NOTE: Checking clientID match if stored token has one
	if rt.RevokedAt != nil {
		if s.refreshReuseDetectionEnabled {
			if rootID, err := tenantData.Tokens().GetFamilyRoot(ctx, rt.ID); err == nil {
				if err := tenantData.Tokens().RevokeFamily(ctx, rootID); err != nil {
					log.Warn("failed to revoke refresh family after reuse", logger.Err(err))
				} else {
					log.Warn("refresh family revoked due to reuse", logger.String("family_root_id", rootID))
				}
			}
			log.Warn("refresh token reuse detected")
		} else {
			log.Warn("refresh token revoked")
		}
		return nil, ErrTokenInvalidGrant
	}
	if !now.Before(rt.ExpiresAt) || (rt.ClientID != "" && rt.ClientID != client.ClientID) {
		log.Warn("refresh token revoked/expired/mismatched")
		return nil, ErrTokenInvalidGrant
	}

	// Build access token claims
	std := map[string]any{
		"tid": tenantSlug,
		"amr": []string{"refresh"},
		"acr": "urn:hellojohn:loa:1",
		"scp": []string{},
	}
	custom := map[string]any{}

	// Resolve effective issuer
	effIss := s.resolveEffectiveIssuer(ctx, tenantSlug)
	accessTTLSeconds := s.effectiveAccessTTLSeconds(ctx, tenantSlug, client.AccessTokenTTL)
	refreshTTLSeconds := s.effectiveRefreshTTLSeconds(ctx, tenantSlug, client.RefreshTokenTTL)

	// Issue new access token with client-specific TTL
	access, exp, err := s.issuer.IssueAccessForTenantWithTTL(tenantSlug, effIss, rt.UserID, req.ClientID, std, custom, accessTTLSeconds)
	if err != nil {
		log.Error("failed to issue access token", logger.Err(err))
		return nil, ErrTokenServerError
	}

	// Rotate refresh token: revoke old, create new with client-specific TTL.
	// Hard fail on revoke error to avoid leaving the previous token active.
	if err := tenantData.Tokens().Revoke(ctx, rt.ID); err != nil {
		log.Error("failed to revoke previous refresh token during rotation", logger.Err(err))
		return nil, ErrTokenServerError
	}

	newRT, err := s.createRefreshTokenWithTTL(ctx, tenantSlug, client.ClientID, rt.UserID, refreshTTLSeconds, &rt.ID)
	if err != nil {
		log.Error("failed to create new refresh token", logger.Err(err))
		return nil, ErrTokenServerError
	}

	log.Info("refresh_token exchanged",
		logger.TenantID(tenantSlug),
		logger.String("client_id", req.ClientID),
	)

	return &TokenResponse{
		AccessToken:  access,
		TokenType:    "Bearer",
		ExpiresIn:    int64(time.Until(exp).Seconds()),
		RefreshToken: newRT,
	}, nil
}

// ExchangeClientCredentials handles grant_type=client_credentials (M2M).
func (s *tokenService) ExchangeClientCredentials(ctx context.Context, req ClientCredentialsRequest) (*TokenResponse, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Op("oauth.token.clientcreds"))

	if req.ClientID == "" {
		return nil, ErrTokenInvalidRequest
	}

	// Lookup client
	client, tenantSlug, err := s.lookupClient(ctx, req.TenantSlug, req.ClientID)
	if err != nil {
		log.Warn("client not found", logger.String("client_id", req.ClientID))
		return nil, ErrTokenInvalidClient
	}

	// Validate grant_type is allowed for this client
	if !isGrantTypeAllowed(client, "client_credentials", s.clientProfilesEnabled) {
		log.Warn("grant_type not allowed for client", logger.String("grant_type", "client_credentials"))
		return nil, ErrTokenUnsupportedGrantType
	}

	// Must be confidential
	if client.Type != repository.ClientTypeConfidential {
		log.Warn("client_credentials requires confidential client")
		return nil, ErrTokenUnauthorizedClient
	}

	// Validate client secret
	if err := s.validateClientSecret(ctx, tenantSlug, client, req.ClientSecret); err != nil {
		log.Warn("invalid client credentials")
		return nil, ErrTokenInvalidClient
	}

	// Validate requested scopes
	reqScopes := []string{}
	// NOTE: default logic if empty?
	if req.Scope != "" {
		reqScopes = strings.Fields(req.Scope)
	}
	for _, scope := range reqScopes {
		if !s.cp.IsScopeAllowed(client, scope) {
			log.Warn("scope not allowed", logger.String("scope", scope))
			return nil, ErrTokenInvalidScope
		}
	}

	// Determine scope output
	var scopeOut string
	if len(reqScopes) > 0 {
		scopeOut = strings.Join(reqScopes, " ")
	} else {
		scopeOut = strings.Join(client.Scopes, " ")
	}

	// Build claims
	std := map[string]any{
		"tid":   tenantSlug,
		"amr":   []string{"client"},
		"acr":   "urn:hellojohn:loa:1",
		"scp":   scopeOut,
		"scope": scopeOut,
	}
	custom := map[string]any{}

	// Resolve effective issuer
	effIss := s.resolveEffectiveIssuer(ctx, tenantSlug)
	accessTTLSeconds := s.effectiveAccessTTLSeconds(ctx, tenantSlug, client.AccessTokenTTL)

	// Issue access token (sub = clientID for M2M) with client-specific TTL
	access, exp, err := s.issuer.IssueAccessForTenantWithTTL(tenantSlug, effIss, req.ClientID, req.ClientID, std, custom, accessTTLSeconds)
	if err != nil {
		log.Error("failed to issue access token", logger.Err(err))
		return nil, ErrTokenServerError
	}

	log.Info("client_credentials token issued",
		logger.TenantID(tenantSlug),
		logger.String("client_id", req.ClientID),
	)

	return &TokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int64(time.Until(exp).Seconds()),
		Scope:       scopeOut,
	}, nil
}

// isGrantTypeAllowed checks grant_type access with optional auth_profile enforcement.
func isGrantTypeAllowed(client *repository.Client, grantType string, clientProfilesEnabled bool) bool {
	if client == nil {
		return false
	}

	grantType = strings.ToLower(strings.TrimSpace(grantType))
	if grantType == "" {
		return false
	}

	// Profile allowlist (feature-flagged).
	if clientProfilesEnabled && !controlplane.ValidateGrant(client.AuthProfile, grantType) {
		return false
	}

	// Explicit client grant_types allowlist.
	if len(client.GrantTypes) == 0 {
		// Backward compatibility when no explicit grant list is configured.
		return true
	}
	for _, g := range client.GrantTypes {
		if strings.EqualFold(strings.TrimSpace(g), grantType) {
			return true
		}
	}
	return false
}

// --- Helper methods ---

func (s *tokenService) lookupClient(ctx context.Context, tenantSlug, clientID string) (*repository.Client, string, error) {
	if s.cp == nil {
		return nil, "", fmt.Errorf("control plane not initialized")
	}

	// Try the provided tenant slug first
	if tenantSlug != "" {
		c, err := s.cp.GetClient(ctx, tenantSlug, clientID)
		if err == nil && c != nil {
			return c, tenantSlug, nil
		}
	}

	// Search across all tenants
	tenants, err := s.cp.ListTenants(ctx)
	if err != nil {
		return nil, "", err
	}
	for _, t := range tenants {
		if t.Slug == tenantSlug {
			continue
		}
		c, err := s.cp.GetClient(ctx, t.Slug, clientID)
		if err == nil && c != nil {
			return c, t.Slug, nil
		}
	}
	return nil, "", fmt.Errorf("client not found")
}

func (s *tokenService) resolveEffectiveIssuer(ctx context.Context, tenantSlug string) string {
	if s.cp == nil || s.issuer == nil {
		if s.issuer != nil {
			return s.issuer.Iss
		}
		return ""
	}
	ten, err := s.cp.GetTenant(ctx, tenantSlug)
	if err != nil || ten == nil {
		return s.issuer.Iss
	}
	return jwtx.ResolveIssuer(s.issuer.Iss, string(ten.Settings.IssuerMode), ten.Slug, ten.Settings.IssuerOverride)
}

func (s *tokenService) validateClientSecret(ctx context.Context, tenantSlug string, client *repository.Client, providedSecret string) error {
	if client.Type != repository.ClientTypeConfidential {
		return nil // only confidential clients have secrets
	}
	dec, err := s.cp.DecryptClientSecret(ctx, tenantSlug, client.ClientID)
	if err != nil {
		return err
	}
	if dec == "" || !subtleEq(dec, providedSecret) {
		return fmt.Errorf("invalid secret")
	}
	return nil
}

func (s *tokenService) createRefreshToken(ctx context.Context, tenantSlug, clientID, userID string) (string, error) {
	return s.createRefreshTokenWithTTL(ctx, tenantSlug, clientID, userID, 0, nil)
}

func (s *tokenService) effectiveAccessTTLSeconds(ctx context.Context, tenantSlug string, clientTTL int) int {
	tenantTTL := 0
	if s.cp != nil {
		if tenant, err := s.cp.GetTenant(ctx, tenantSlug); err == nil && tenant != nil {
			tenantTTL = tenant.Settings.SessionLifetimeSeconds
		}
	}
	return resolveEffectiveTTLSeconds(clientTTL, tenantTTL, s.issuer.AccessTTL)
}

func (s *tokenService) effectiveRefreshTTLSeconds(ctx context.Context, tenantSlug string, clientTTL int) int {
	tenantTTL := 0
	if s.cp != nil {
		if tenant, err := s.cp.GetTenant(ctx, tenantSlug); err == nil && tenant != nil {
			tenantTTL = tenant.Settings.RefreshTokenLifetimeSeconds
		}
	}
	return resolveEffectiveTTLSeconds(clientTTL, tenantTTL, s.refreshTTL)
}

func resolveEffectiveTTLSeconds(clientTTL int, tenantTTL int, globalTTL time.Duration) int {
	if clientTTL > 0 {
		return clientTTL
	}
	if tenantTTL > 0 {
		return tenantTTL
	}
	seconds := int(globalTTL.Seconds())
	if seconds <= 0 {
		return 1
	}
	return seconds
}

// createRefreshTokenWithTTL creates a refresh token with optional client-specific TTL.
// If ttlSeconds <= 0, uses the default service TTL.
func (s *tokenService) createRefreshTokenWithTTL(ctx context.Context, tenantSlug, clientID, userID string, ttlSeconds int, rotatedFrom *string) (string, error) {
	// Generate opaque token
	rawRT, err := tokens.GenerateOpaqueToken(32)
	if err != nil {
		return "", err
	}

	// Get tenant data access
	tenantData, err := s.dal.ForTenant(ctx, tenantSlug)
	if err != nil {
		return "", fmt.Errorf("tenant data access: %w", err)
	}
	tenantID := strings.TrimSpace(tenantData.ID())
	if tenantID == "" {
		return "", fmt.Errorf("tenant canonical id is empty")
	}

	// Store hashed refresh token
	tokenHash := tokens.SHA256Base64URL(rawRT)

	// Use client-specific TTL if provided, otherwise use service default
	effectiveTTL := int(s.refreshTTL.Seconds())
	if ttlSeconds > 0 {
		effectiveTTL = ttlSeconds
	}

	// Create refresh token in repo
	_, err = tenantData.Tokens().Create(ctx, repository.CreateRefreshTokenInput{
		TenantID:    tenantID,
		ClientID:    clientID,
		UserID:      userID,
		TokenHash:   tokenHash,
		TTLSeconds:  effectiveTTL,
		RotatedFrom: rotatedFrom,
	})
	if err != nil {
		return "", fmt.Errorf("store refresh token: %w", err)
	}

	return rawRT, nil
}

// atHash computes at_hash = base64url(left-most 128 bits of SHA-256(access_token))
func atHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// subtleEq performs constant-time string comparison using crypto/subtle.
// It normalizes both inputs to the same length to avoid early-return behavior
// on length mismatch, and combines content+length checks without branching.
func subtleEq(a, b string) bool {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}

	ab := make([]byte, n)
	bb := make([]byte, n)
	copy(ab, a)
	copy(bb, b)

	contentEq := subtle.ConstantTimeCompare(ab, bb)
	lengthEq := subtle.ConstantTimeEq(int32(len(a)), int32(len(b)))
	return (contentEq & lengthEq) == 1
}

// enrichClaimsFromScopes adds user claims based on scope configuration.
// For each scope, it looks up the configured claims and adds them to the claims map.
func (s *tokenService) enrichClaimsFromScopes(ctx context.Context, claims map[string]any, tenantSlug string, user *repository.User, requestedScopes []string) {
	if s.cp == nil || user == nil {
		return
	}

	// Get all scopes for the tenant
	allScopes, err := s.cp.ListScopes(ctx, tenantSlug)
	if err != nil {
		return // silently continue without enrichment
	}

	// Build scope name -> scope map
	scopeMap := make(map[string]*repository.Scope)
	for i := range allScopes {
		scopeMap[allScopes[i].Name] = &allScopes[i]
	}

	// Process each requested scope
	for _, scopeName := range requestedScopes {
		scope, ok := scopeMap[scopeName]
		if !ok || len(scope.Claims) == 0 {
			continue
		}

		// Add claims configured for this scope
		for _, claimName := range scope.Claims {
			if value := getUserClaimValue(user, claimName); value != nil {
				claims[claimName] = value
			}
		}
	}

	// Also handle standard OIDC scopes that aren't necessarily configured
	for _, scopeName := range requestedScopes {
		switch scopeName {
		case "profile":
			if user.Name != "" {
				claims["name"] = user.Name
			}
			if user.GivenName != "" {
				claims["given_name"] = user.GivenName
			}
			if user.FamilyName != "" {
				claims["family_name"] = user.FamilyName
			}
			if user.Picture != "" {
				claims["picture"] = user.Picture
			}
			if user.Locale != "" {
				claims["locale"] = user.Locale
			}
		case "email":
			claims["email"] = user.Email
			claims["email_verified"] = user.EmailVerified
		}
	}
}

// getUserClaimValue extracts a claim value from a user object.
func getUserClaimValue(user *repository.User, claimName string) any {
	switch claimName {
	case "sub":
		return user.ID
	case "name":
		if user.Name != "" {
			return user.Name
		}
	case "given_name":
		if user.GivenName != "" {
			return user.GivenName
		}
	case "family_name":
		if user.FamilyName != "" {
			return user.FamilyName
		}
	case "email":
		return user.Email
	case "email_verified":
		return user.EmailVerified
	case "picture":
		if user.Picture != "" {
			return user.Picture
		}
	case "locale":
		if user.Locale != "" {
			return user.Locale
		}
	case "language":
		if user.Language != "" {
			return user.Language
		}
	default:
		// Check in metadata
		if user.Metadata != nil {
			if val, ok := user.Metadata[claimName]; ok {
				return val
			}
		}
		// Check in custom fields
		if user.CustomFields != nil {
			if val, ok := user.CustomFields[claimName]; ok {
				return val
			}
		}
	}
	return nil
}
