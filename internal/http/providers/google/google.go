// Package google implements the Google OIDC provider.
package google

import (
	"context"
	"fmt"

	"github.com/dropDatabas3/hellojohn/internal/http/providers"
)

const ProviderName = "google"

// Provider implements the Google OIDC authentication flow.
type Provider struct {
	clientID     string
	clientSecret string
	redirectURI  string
	scopes       []string
}

// Factory creates a new Google provider.
func Factory(cfg providers.ProviderConfig) (providers.Provider, error) {
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("google: client_id required")
	}
	return &Provider{
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		redirectURI:  cfg.RedirectURI,
		scopes:       cfg.Scopes,
	}, nil
}

// Name returns the provider name.
func (p *Provider) Name() string { return ProviderName }

// Type returns the provider type (OIDC).
func (p *Provider) Type() providers.ProviderType { return providers.ProviderTypeOIDC }

// Configure updates the provider configuration.
func (p *Provider) Configure(cfg providers.ProviderConfig) error {
	p.clientID = cfg.ClientID
	p.clientSecret = cfg.ClientSecret
	p.redirectURI = cfg.RedirectURI
	p.scopes = cfg.Scopes
	return nil
}

// Validate checks if the provider is properly configured.
func (p *Provider) Validate() error {
	if p.clientID == "" {
		return fmt.Errorf("google: client_id not configured")
	}
	return nil
}

// AuthorizeURL builds the Google authorization URL.
// TODO: Implement full OAuth2/OIDC authorization URL builder.
func (p *Provider) AuthorizeURL(state, nonce string, scopes []string) string {
	// Placeholder - implement with proper URL building
	return fmt.Sprintf("https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&state=%s", p.clientID, state)
}

// Exchange trades an authorization code for tokens.
// TODO: Implement OAuth2 token exchange.
func (p *Provider) Exchange(ctx context.Context, code string) (*providers.TokenSet, error) {
	return nil, fmt.Errorf("google: Exchange not implemented")
}

// UserInfo fetches the user profile from Google.
// TODO: Implement OIDC userinfo endpoint call.
func (p *Provider) UserInfo(ctx context.Context, accessToken string) (*providers.UserProfile, error) {
	return nil, fmt.Errorf("google: UserInfo not implemented")
}
