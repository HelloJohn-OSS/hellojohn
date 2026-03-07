package social

import (
	"context"
	"fmt"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/oauth/github"
	"github.com/dropDatabas3/hellojohn/internal/oauth/google"
	sec "github.com/dropDatabas3/hellojohn/internal/security/secretbox"
)

// OIDCClient provides OAuth/OIDC operations for a provider.
type OIDCClient interface {
	// AuthURL returns the authorization URL for redirecting the user.
	AuthURL(ctx context.Context, state, nonce string) (string, error)
	// ExchangeCode exchanges an authorization code for tokens.
	ExchangeCode(ctx context.Context, code string) (*OIDCTokens, error)
	// VerifyIDToken verifies an ID token and returns claims.
	VerifyIDToken(ctx context.Context, idToken, nonce string) (*OIDCClaims, error)
}

// OIDCTokens contains tokens from code exchange.
type OIDCTokens struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	ExpiresIn    int
}

// OIDCClaims contains claims from ID token.
type OIDCClaims struct {
	Sub           string
	Email         string
	EmailVerified bool
	Name          string
	GivenName     string
	FamilyName    string
	Picture       string
	Locale        string
	Nonce         string
}

// ─────────────────────────────────────────────────────────────
// Google ProviderFactory (migrado desde DefaultOIDCFactory.Google)
// ─────────────────────────────────────────────────────────────

// GoogleFactory implementa ProviderFactory para Google OIDC.
type GoogleFactory struct {
	TenantProvider TenantProvider
}

func (f *GoogleFactory) Build(ctx context.Context, tenantSlug, baseURL string) (OIDCClient, error) {
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

	if !settings.SocialLoginEnabled && !settings.SocialProviders.GoogleEnabled {
		return nil, fmt.Errorf("google not enabled for tenant")
	}

	clientID := settings.SocialProviders.GoogleClient
	secretEnc := settings.SocialProviders.GoogleSecretEnc

	if clientID == "" {
		return nil, fmt.Errorf("google client_id not configured")
	}

	clientSecret, err := decryptSecret(secretEnc, "google")
	if err != nil {
		return nil, err
	}

	redirectURL := fmt.Sprintf("%s/v2/auth/social/google/callback", strings.TrimRight(baseURL, "/"))
	oidc := google.New(clientID, clientSecret, redirectURL, []string{"openid", "profile", "email"})

	return &googleOIDCAdapter{oidc: oidc}, nil
}

// googleOIDCAdapter adapts google.OIDC to OIDCClient interface.
type googleOIDCAdapter struct {
	oidc *google.OIDC
}

func (a *googleOIDCAdapter) AuthURL(ctx context.Context, state, nonce string) (string, error) {
	return a.oidc.AuthURL(ctx, state, nonce)
}

func (a *googleOIDCAdapter) ExchangeCode(ctx context.Context, code string) (*OIDCTokens, error) {
	resp, err := a.oidc.ExchangeCode(ctx, code)
	if err != nil {
		return nil, err
	}
	return &OIDCTokens{
		AccessToken:  resp.AccessToken,
		IDToken:      resp.IDToken,
		RefreshToken: resp.RefreshTok,
		ExpiresIn:    resp.ExpiresIn,
	}, nil
}

func (a *googleOIDCAdapter) VerifyIDToken(ctx context.Context, idToken, nonce string) (*OIDCClaims, error) {
	claims, err := a.oidc.VerifyIDToken(ctx, idToken, nonce)
	if err != nil {
		return nil, err
	}
	return &OIDCClaims{
		Sub:           claims.Sub,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Name:          claims.Name,
		GivenName:     claims.GivenName,
		FamilyName:    claims.FamilyName,
		Picture:       claims.Picture,
		Locale:        claims.Locale,
		Nonce:         claims.Nonce,
	}, nil
}

// ─────────────────────────────────────────────────────────────
// GitHub ProviderFactory (migrado desde DefaultOIDCFactory.GitHub)
// ─────────────────────────────────────────────────────────────

// GitHubFactory implementa ProviderFactory para GitHub OAuth.
type GitHubFactory struct {
	TenantProvider TenantProvider
}

func (f *GitHubFactory) Build(ctx context.Context, tenantSlug, baseURL string) (OIDCClient, error) {
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

	if !settings.SocialLoginEnabled && !settings.SocialProviders.GitHubEnabled {
		return nil, fmt.Errorf("github not enabled for tenant")
	}

	clientID := settings.SocialProviders.GitHubClient
	secretEnc := settings.SocialProviders.GitHubSecretEnc

	if clientID == "" {
		return nil, fmt.Errorf("github client_id not configured")
	}

	clientSecret, err := decryptSecret(secretEnc, "github")
	if err != nil {
		return nil, err
	}

	redirectURL := fmt.Sprintf("%s/v2/auth/social/github/callback", strings.TrimRight(baseURL, "/"))
	oauth := github.New(clientID, clientSecret, redirectURL, []string{"user:email", "read:user"})

	return &githubOAuthAdapter{oauth: oauth}, nil
}

// githubOAuthAdapter adapts github.OAuth to OIDCClient interface.
type githubOAuthAdapter struct {
	oauth *github.OAuth
}

func (a *githubOAuthAdapter) AuthURL(ctx context.Context, state, nonce string) (string, error) {
	return a.oauth.AuthURL(ctx, state, nonce)
}

func (a *githubOAuthAdapter) ExchangeCode(ctx context.Context, code string) (*OIDCTokens, error) {
	resp, err := a.oauth.ExchangeCode(ctx, code)
	if err != nil {
		return nil, err
	}
	return &OIDCTokens{
		AccessToken: resp.AccessToken,
		IDToken:     "",
	}, nil
}

func (a *githubOAuthAdapter) VerifyIDToken(ctx context.Context, idToken, nonce string) (*OIDCClaims, error) {
	accessToken := strings.TrimSpace(idToken)
	if accessToken == "" {
		return nil, fmt.Errorf("no access token available")
	}

	userInfo, err := a.oauth.GetUserWithEmail(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get github user info: %w", err)
	}

	return &OIDCClaims{
		Sub:           fmt.Sprintf("%d", userInfo.ID),
		Email:         userInfo.Email,
		EmailVerified: true,
		Name:          userInfo.Name,
		Picture:       userInfo.AvatarURL,
		Nonce:         nonce,
	}, nil
}

// ─────────────────────────────────────────────────────────────
// Helpers compartidos
// ─────────────────────────────────────────────────────────────

// decryptSecret descifra un secreto encriptado. Si no tiene el separador "|" de secretbox,
// lo trata como plaintext (modo dev).
func decryptSecret(secretEnc, providerName string) (string, error) {
	if secretEnc == "" {
		return "", fmt.Errorf("%s client_secret not configured", providerName)
	}

	plainSecret, err := sec.Decrypt(secretEnc)
	if err != nil {
		if !strings.Contains(secretEnc, "|") {
			return secretEnc, nil // Fallback: plaintext dev mode
		}
		return "", fmt.Errorf("failed to decrypt %s secret: %w", providerName, err)
	}
	return plainSecret, nil
}
