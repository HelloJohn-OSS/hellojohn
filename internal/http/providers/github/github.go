// Package github implements the GitHub OAuth2 provider.
package github

import (
	"context"
	"fmt"

	"github.com/dropDatabas3/hellojohn/internal/http/providers"
)

const ProviderName = "github"

// Provider implements GitHub OAuth2 authentication.
// TODO: Implement when adding GitHub support.
type Provider struct {
	clientID     string
	clientSecret string
	redirectURI  string
	scopes       []string
}

// Factory creates a new GitHub provider.
func Factory(cfg providers.ProviderConfig) (providers.Provider, error) {
	return &Provider{
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		redirectURI:  cfg.RedirectURI,
		scopes:       cfg.Scopes,
	}, nil
}

func (p *Provider) Name() string                                             { return ProviderName }
func (p *Provider) Type() providers.ProviderType                             { return providers.ProviderTypeOAuth2 }
func (p *Provider) Configure(cfg providers.ProviderConfig) error             { return nil }
func (p *Provider) Validate() error                                          { return fmt.Errorf("github: not implemented") }
func (p *Provider) AuthorizeURL(state, nonce string, scopes []string) string { return "" }
func (p *Provider) Exchange(ctx context.Context, code string) (*providers.TokenSet, error) {
	return nil, fmt.Errorf("github: not implemented")
}
func (p *Provider) UserInfo(ctx context.Context, accessToken string) (*providers.UserProfile, error) {
	return nil, fmt.Errorf("github: not implemented")
}
