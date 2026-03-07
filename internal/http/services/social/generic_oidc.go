package social

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// GenericOIDCFactory implementa ProviderFactory para proveedores OIDC genéricos
// (GitLab, Keycloak, custom enterprise SSO, etc.) vía auto-discovery.
type GenericOIDCFactory struct {
	TenantProvider TenantProvider
}

const defaultOIDCDiscoveryCacheTTL = 15 * time.Minute

type oidcDiscoveryCacheEntry struct {
	discovery *oidcDiscovery
	expiresAt time.Time
}

var oidcDiscoveryCache = struct {
	mu      sync.RWMutex
	entries map[string]oidcDiscoveryCacheEntry
}{
	entries: make(map[string]oidcDiscoveryCacheEntry),
}

// GenericOIDCResolver is used by start/callback flows to resolve custom alias providers.
type GenericOIDCResolver interface {
	BuildForAlias(ctx context.Context, tenantSlug, baseURL, alias string) (OIDCClient, error)
}

// Build for GenericOIDC requires the provider name to match a CustomOIDCConfig alias.
func (f *GenericOIDCFactory) Build(ctx context.Context, tenantSlug, baseURL string) (OIDCClient, error) {
	// GenericOIDCFactory necesita saber cuál alias buscar.
	// Como ProviderFactory.Build no tiene un param de alias, usamos BuildForAlias directamente.
	// Este método se invoca como fallback cuando el Registry no tiene un match exacto.
	return nil, fmt.Errorf("generic OIDC requires alias-based lookup; use BuildForAlias instead")
}

// BuildForAlias crea un OIDCClient para un alias de CustomOIDCConfig específico.
func (f *GenericOIDCFactory) BuildForAlias(ctx context.Context, tenantSlug, baseURL, alias string) (OIDCClient, error) {
	if f.TenantProvider == nil {
		return nil, fmt.Errorf("tenant provider not configured")
	}

	tenant, err := f.TenantProvider.GetTenant(ctx, tenantSlug)
	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	settings := &tenant.Settings
	if settings.SocialProviders == nil {
		return nil, fmt.Errorf("social providers not configured")
	}

	// Find the matching custom OIDC config
	var cfg *customOIDCRef
	for _, p := range settings.SocialProviders.CustomOIDCProviders {
		if strings.EqualFold(p.Alias, alias) && p.Enabled {
			cfg = &customOIDCRef{
				alias:        p.Alias,
				wellKnownURL: p.WellKnownURL,
				clientID:     p.ClientID,
				secretEnc:    p.ClientSecretEnc,
				scopes:       p.Scopes,
			}
			break
		}
	}
	if cfg == nil {
		return nil, fmt.Errorf("custom OIDC provider %q not found or disabled", alias)
	}

	if cfg.wellKnownURL == "" || cfg.clientID == "" {
		return nil, fmt.Errorf("custom OIDC %q: wellKnownUrl and clientId are required", alias)
	}

	clientSecret, err := decryptSecret(cfg.secretEnc, "oidc:"+alias)
	if err != nil {
		return nil, err
	}

	// Discover endpoints from .well-known/openid-configuration
	httpClient := sharedSocialHTTPClient()
	discovery, err := discoverOIDC(ctx, cfg.wellKnownURL, httpClient)
	if err != nil {
		return nil, fmt.Errorf("custom OIDC %q discovery failed: %w", alias, err)
	}

	scopes := cfg.scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	redirectURL := fmt.Sprintf("%s/v2/auth/social/%s/callback",
		strings.TrimRight(baseURL, "/"), alias)

	return &genericOIDCAdapter{
		clientID:         cfg.clientID,
		clientSecret:     clientSecret,
		redirectURL:      redirectURL,
		scopes:           scopes,
		authEndpoint:     discovery.AuthorizationEndpoint,
		tokenEndpoint:    discovery.TokenEndpoint,
		userinfoEndpoint: discovery.UserinfoEndpoint,
		httpClient:       httpClient,
	}, nil
}

type customOIDCRef struct {
	alias, wellKnownURL, clientID, secretEnc string
	scopes                                   []string
}

type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	Issuer                string `json:"issuer"`
}

func discoverOIDC(ctx context.Context, wellKnownURL string, httpClient *http.Client) (*oidcDiscovery, error) {
	cacheKey := strings.TrimSpace(wellKnownURL)
	if cacheKey == "" {
		return nil, fmt.Errorf("well-known URL required")
	}

	now := time.Now()
	oidcDiscoveryCache.mu.RLock()
	cached, hasCached := oidcDiscoveryCache.entries[cacheKey]
	oidcDiscoveryCache.mu.RUnlock()

	if hasCached && cached.discovery != nil && now.Before(cached.expiresAt) {
		return cached.discovery, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cacheKey, nil)
	if err != nil {
		return nil, err
	}

	client := httpClient
	if client == nil {
		client = sharedSocialHTTPClient()
	}
	resp, err := client.Do(req)
	if err != nil {
		if hasCached && cached.discovery != nil {
			return cached.discovery, nil
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery endpoint returned status %d", resp.StatusCode)
	}

	var disco oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&disco); err != nil {
		return nil, fmt.Errorf("discovery decode: %w", err)
	}

	if disco.AuthorizationEndpoint == "" || disco.TokenEndpoint == "" {
		return nil, fmt.Errorf("discovery response missing required endpoints")
	}

	discovery := &disco
	oidcDiscoveryCache.mu.Lock()
	oidcDiscoveryCache.entries[cacheKey] = oidcDiscoveryCacheEntry{
		discovery: discovery,
		expiresAt: now.Add(defaultOIDCDiscoveryCacheTTL),
	}
	oidcDiscoveryCache.mu.Unlock()

	return discovery, nil
}

type genericOIDCAdapter struct {
	clientID, clientSecret, redirectURL           string
	scopes                                        []string
	authEndpoint, tokenEndpoint, userinfoEndpoint string
	httpClient                                    *http.Client
}

func (a *genericOIDCAdapter) AuthURL(_ context.Context, state, nonce string) (string, error) {
	params := url.Values{
		"client_id":     {a.clientID},
		"redirect_uri":  {a.redirectURL},
		"response_type": {"code"},
		"scope":         {strings.Join(a.scopes, " ")},
		"state":         {state},
		"nonce":         {nonce},
	}
	return a.authEndpoint + "?" + params.Encode(), nil
}

func (a *genericOIDCAdapter) ExchangeCode(ctx context.Context, code string) (*OIDCTokens, error) {
	data := url.Values{
		"client_id":     {a.clientID},
		"client_secret": {a.clientSecret},
		"code":          {code},
		"redirect_uri":  {a.redirectURL},
		"grant_type":    {"authorization_code"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.tokenEndpoint,
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("generic oidc token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("generic oidc token exchange: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("generic oidc token exchange: status %d", resp.StatusCode)
	}

	var tok struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, fmt.Errorf("generic oidc token decode: %w", err)
	}

	return &OIDCTokens{
		AccessToken:  tok.AccessToken,
		IDToken:      tok.IDToken,
		RefreshToken: tok.RefreshToken,
		ExpiresIn:    tok.ExpiresIn,
	}, nil
}

// VerifyIDToken for generic OIDC uses the userinfo endpoint.
func (a *genericOIDCAdapter) VerifyIDToken(ctx context.Context, idToken, _ string) (*OIDCClaims, error) {
	accessToken := strings.TrimSpace(idToken)
	if accessToken == "" {
		return nil, fmt.Errorf("no access token available")
	}

	if a.userinfoEndpoint == "" {
		return nil, fmt.Errorf("generic oidc: userinfo_endpoint not available from discovery")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.userinfoEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("generic oidc userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("generic oidc userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("generic oidc userinfo: status %d", resp.StatusCode)
	}

	var body struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Picture       string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("generic oidc userinfo decode: %w", err)
	}

	return &OIDCClaims{
		Sub:           body.Sub,
		Email:         body.Email,
		EmailVerified: body.EmailVerified,
		Name:          body.Name,
		GivenName:     body.GivenName,
		FamilyName:    body.FamilyName,
		Picture:       body.Picture,
	}, nil
}
