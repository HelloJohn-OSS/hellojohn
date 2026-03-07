// Package oauth contains services for OAuth2/OIDC endpoints.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	controlplane "github.com/dropDatabas3/hellojohn/internal/controlplane"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/oauth"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// Cache key prefixes
const (
	cacheKeyPrefixSID    = "sid:"
	cacheKeyPrefixCode   = "code:"
	cacheKeyPrefixMFAReq = "mfa_req:"
)

// TTL constants
const (
	authCodeTTL     = 10 * time.Minute
	mfaChallengeTTL = 5 * time.Minute
)

// Errors for authorize flow
var (
	ErrMissingParams   = errors.New("missing required parameters")
	ErrInvalidScope    = errors.New("scope must include openid")
	ErrPKCERequired    = errors.New("PKCE S256 required")
	ErrInvalidClient   = errors.New("invalid client")
	ErrInvalidRedirect = errors.New("redirect_uri not allowed")
	ErrScopeNotAllowed = errors.New("scope not allowed for client")
	ErrGrantNotAllowed = errors.New("grant not allowed for client profile")
	ErrCodeGenFailed   = errors.New("failed to generate auth code")
)

// AuthorizeService handles the OAuth2 authorization flow.
type AuthorizeService interface {
	Authorize(ctx context.Context, r *http.Request, req dto.AuthorizeRequest) (dto.AuthResult, error)
}

// CacheClient abstracts cache operations needed by authorize.
type CacheClient interface {
	Get(key string) ([]byte, bool)
	Set(key string, value []byte, ttl time.Duration)
	Delete(key string) // Added for token endpoint's one-shot code consumption
}

// AuthorizeDeps contains dependencies for AuthorizeService.
type AuthorizeDeps struct {
	DAL                   store.DataAccessLayer
	ControlPlane          controlplane.Service
	Cache                 CacheClient
	Issuer                *jwtx.Issuer
	CookieName            string
	AllowBearer           bool
	UIBaseURL             string // Default: "http://localhost:3000"
	ClientProfilesEnabled bool
}

type authorizeService struct {
	dal                   store.DataAccessLayer
	cp                    controlplane.Service
	cache                 CacheClient
	issuer                *jwtx.Issuer
	cookieName            string
	allowBearer           bool
	uiBaseURL             string
	clientProfilesEnabled bool
}

// NewAuthorizeService creates a new AuthorizeService.
func NewAuthorizeService(d AuthorizeDeps) AuthorizeService {
	uiBase := d.UIBaseURL
	if uiBase == "" {
		uiBase = "http://localhost:3000"
	}
	return &authorizeService{
		dal:                   d.DAL,
		cp:                    d.ControlPlane,
		cache:                 d.Cache,
		issuer:                d.Issuer,
		cookieName:            d.CookieName,
		allowBearer:           d.AllowBearer,
		uiBaseURL:             uiBase,
		clientProfilesEnabled: d.ClientProfilesEnabled,
	}
}

// Authorize handles the full authorization flow.
func (s *authorizeService) Authorize(ctx context.Context, r *http.Request, req dto.AuthorizeRequest) (dto.AuthResult, error) {
	log := logger.From(ctx).With(logger.Layer("service"), logger.Op("AuthorizeService.Authorize"))

	// 1. Validate request
	if err := s.validateRequest(req); err != nil {
		return dto.AuthResult{}, err
	}

	// 2. Resolve client and validate redirect/scopes
	client, tenantSlug, err := s.resolveClient(ctx, req.ClientID)
	if err != nil {
		log.Debug("client resolution failed", logger.Err(err), logger.ClientID(req.ClientID))
		return dto.AuthResult{}, ErrInvalidClient
	}
	if !isGrantAllowedForAuthorize(client, s.clientProfilesEnabled) {
		log.Debug("authorization_code not allowed for client profile",
			logger.String("auth_profile", strings.TrimSpace(client.AuthProfile)),
			logger.ClientID(client.ClientID),
		)
		return dto.AuthResult{}, ErrGrantNotAllowed
	}

	if err := s.validateRedirectURI(client, req.RedirectURI); err != nil {
		log.Debug("redirect validation failed", logger.Err(err))
		return dto.AuthResult{}, ErrInvalidRedirect
	}

	if err := s.validateScopes(client, req.Scope); err != nil {
		log.Debug("scope validation failed", logger.Err(err))
		return dto.AuthResult{
			Type:             dto.AuthResultError,
			RedirectURI:      req.RedirectURI,
			ErrorCode:        "invalid_scope",
			ErrorDescription: "scope not allowed",
		}, nil
	}

	// 3. Authenticate user (session cookie or bearer)
	sub, tid, amr, authenticated := s.authenticate(ctx, r, tenantSlug)
	log.Debug("auth result", logger.Bool("authenticated", authenticated), logger.UserID(sub), logger.TenantSlug(tid))

	// 4. Not authenticated or tenant mismatch
	if !authenticated || !strings.EqualFold(tid, tenantSlug) {
		if strings.Contains(req.Prompt, "none") {
			return dto.AuthResult{
				Type:             dto.AuthResultError,
				RedirectURI:      req.RedirectURI,
				ErrorCode:        "login_required",
				ErrorDescription: "login required",
			}, nil
		}

		loginURL := s.buildLoginURL(r)
		return dto.AuthResult{
			Type:     dto.AuthResultNeedLogin,
			LoginURL: loginURL,
		}, nil
	}

	// 5. MFA step-up check
	if len(amr) == 1 && amr[0] == "pwd" {
		needMFA, mfaToken, err := s.checkMFAStepUp(ctx, r, sub, tid, req.ClientID, req.Scope)
		if err != nil {
			log.Debug("MFA check failed", logger.Err(err))
		}
		if needMFA {
			return dto.AuthResult{
				Type:     dto.AuthResultMFARequired,
				MFAToken: mfaToken,
			}, nil
		}
		// If trusted device, AMR was elevated
		if !needMFA && mfaToken == "" {
			amr = append(amr, "mfa", "totp")
		}
	}

	// 6. Generate auth code and store in cache
	code, err := tokens.GenerateOpaqueToken(32)
	if err != nil {
		log.Error("code generation failed", logger.Err(err))
		return dto.AuthResult{}, ErrCodeGenFailed
	}

	payload := dto.AuthCodePayload{
		UserID:          sub,
		TenantID:        tid,
		ClientID:        req.ClientID,
		RedirectURI:     req.RedirectURI,
		Scope:           req.Scope,
		Nonce:           req.Nonce,
		CodeChallenge:   req.CodeChallenge,
		ChallengeMethod: req.CodeChallengeMethod,
		AMR:             amr,
		ExpiresAt:       time.Now().Add(authCodeTTL),
	}
	payloadBytes, _ := json.Marshal(payload)
	// Store hashed code in cache (hardening)
	codeHash := tokens.SHA256Base64URL(code)
	s.cache.Set(cacheKeyPrefixCode+codeHash, payloadBytes, authCodeTTL)

	log.Info("auth code issued", logger.UserID(sub), logger.TenantSlug(tid), logger.ClientID(req.ClientID))

	return dto.AuthResult{
		Type:        dto.AuthResultSuccess,
		Code:        code,
		State:       req.State,
		RedirectURI: req.RedirectURI,
	}, nil
}

// validateRequest checks required params for authorize.
func (s *authorizeService) validateRequest(req dto.AuthorizeRequest) error {
	if req.ResponseType != "code" || req.ClientID == "" || req.RedirectURI == "" || req.Scope == "" {
		return ErrMissingParams
	}
	if !strings.Contains(req.Scope, "openid") {
		return ErrInvalidScope
	}
	if !strings.EqualFold(req.CodeChallengeMethod, "S256") || req.CodeChallenge == "" {
		return ErrPKCERequired
	}
	return nil
}

// resolveClient looks up the client and returns it with tenant slug.
func (s *authorizeService) resolveClient(ctx context.Context, clientID string) (*repository.Client, string, error) {
	if s.cp == nil {
		return nil, "", ErrInvalidClient
	}

	// Iterate tenants to find the client
	tenants, err := s.cp.ListTenants(ctx)
	if err != nil {
		return nil, "", err
	}

	for _, t := range tenants {
		client, err := s.cp.GetClient(ctx, t.Slug, clientID)
		if err == nil && client != nil {
			return client, t.Slug, nil
		}
	}

	return nil, "", ErrInvalidClient
}

// validateRedirectURI checks if the URI is allowed for the client.
func (s *authorizeService) validateRedirectURI(client *repository.Client, uri string) error {
	if client == nil {
		return ErrInvalidClient
	}
	for _, allowed := range client.RedirectURIs {
		if allowed == uri {
			return nil
		}
	}
	return ErrInvalidRedirect
}

// validateScopes checks if all requested scopes are allowed.
func (s *authorizeService) validateScopes(client *repository.Client, scopeStr string) error {
	for _, scope := range strings.Fields(scopeStr) {
		if !s.cp.IsScopeAllowed(client, scope) {
			return ErrScopeNotAllowed
		}
	}
	return nil
}

func isGrantAllowedForAuthorize(client *repository.Client, clientProfilesEnabled bool) bool {
	if client == nil {
		return false
	}

	// Profile gating (feature-flagged).
	if clientProfilesEnabled && !controlplane.ValidateGrant(client.AuthProfile, "authorization_code") {
		return false
	}

	// Explicit client grant list must also allow authorization_code.
	if len(client.GrantTypes) == 0 {
		return true
	}
	for _, g := range client.GrantTypes {
		if strings.EqualFold(strings.TrimSpace(g), "authorization_code") {
			return true
		}
	}
	return false
}

// authenticate tries cookie session first, then bearer token.
func (s *authorizeService) authenticate(ctx context.Context, r *http.Request, expectedTenant string) (sub, tid string, amr []string, ok bool) {
	// 1. Try session cookie
	if ck, err := r.Cookie(s.cookieName); err == nil && ck != nil && strings.TrimSpace(ck.Value) != "" {
		key := cacheKeyPrefixSID + tokens.SHA256Base64URL(ck.Value)
		if b, found := s.cache.Get(key); found {
			var sp dto.SessionPayload
			if json.Unmarshal(b, &sp) == nil {
				if time.Now().Before(sp.Expires) && strings.EqualFold(sp.TenantID, expectedTenant) {
					return sp.UserID, sp.TenantID, []string{"pwd"}, true
				}
			}
		}
	}

	// 2. Fallback to bearer token
	if s.allowBearer && s.issuer != nil {
		ah := strings.TrimSpace(r.Header.Get("Authorization"))
		if strings.HasPrefix(strings.ToLower(ah), "bearer ") {
			raw := strings.TrimSpace(ah[len("Bearer "):])
			tk, err := jwtv5.Parse(raw, s.issuer.Keyfunc(),
				jwtv5.WithValidMethods([]string{"EdDSA"}),
				jwtv5.WithIssuer(s.issuer.Iss))
			if err == nil && tk.Valid {
				if claims, ok := tk.Claims.(jwtv5.MapClaims); ok {
					sub, _ = claims["sub"].(string)
					tid, _ = claims["tid"].(string)
					if v, ok := claims["amr"].([]any); ok {
						for _, i := range v {
							if s, ok := i.(string); ok {
								amr = append(amr, s)
							}
						}
					}
					if sub != "" && tid != "" {
						return sub, tid, amr, true
					}
				}
			}
		}
	}

	return "", "", nil, false
}

// checkMFAStepUp checks if user needs MFA verification.
// Returns (needMFA, mfaToken, error). If trusted device, needMFA=false and mfaToken="".
func (s *authorizeService) checkMFAStepUp(ctx context.Context, r *http.Request, userID, tenantID, clientID, scope string) (bool, string, error) {
	// Get tenant data access
	tda, err := s.dal.ForTenant(ctx, tenantID)
	if err != nil {
		return false, "", nil // No DB, skip MFA check
	}

	// Check if user has confirmed TOTP
	mfaRepo := tda.MFA()
	if mfaRepo == nil {
		return false, "", nil
	}

	totp, err := mfaRepo.GetTOTP(ctx, userID)
	if err != nil || totp == nil || totp.ConfirmedAt == nil {
		return false, "", nil // No confirmed TOTP
	}

	// Check trusted device cookie
	if ck, err := r.Cookie("mfa_trust"); err == nil && ck != nil {
		deviceHash := tokens.SHA256Base64URL(ck.Value)
		trusted, _ := mfaRepo.IsTrustedDevice(ctx, userID, deviceHash)
		if trusted {
			return false, "", nil // Trusted device, no MFA needed
		}
	}

	// Create MFA challenge
	challenge := dto.MFAChallenge{
		UserID:   userID,
		TenantID: tenantID,
		ClientID: clientID,
		AMRBase:  []string{"pwd"},
		Scope:    strings.Fields(scope),
	}
	challengeBytes, _ := json.Marshal(challenge)

	mid, err := tokens.GenerateOpaqueToken(24)
	if err != nil {
		return false, "", err
	}

	s.cache.Set(cacheKeyPrefixMFAReq+mid, challengeBytes, mfaChallengeTTL)

	return true, mid, nil
}

// buildLoginURL constructs the URL to redirect for login.
func (s *authorizeService) buildLoginURL(r *http.Request) string {
	// Build return_to from current request
	returnTo := r.URL.String()
	if !r.URL.IsAbs() {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		host := r.Host
		if host == "" {
			host = "localhost:8080"
		}
		returnTo = fmt.Sprintf("%s://%s%s", scheme, host, r.URL.RequestURI())
	}

	return fmt.Sprintf("%s/login?return_to=%s", s.uiBaseURL, url.QueryEscape(returnTo))
}
