// Package microsoft implements the Microsoft (Azure AD) OAuth2/OIDC provider.
package microsoft

import (
	"context"
	"fmt"

	"github.com/dropDatabas3/hellojohn/internal/http/providers"
)

const ProviderName = "microsoft"

// Provider implements Microsoft OAuth2/OIDC authentication.
// Supports both personal accounts and Azure AD work/school accounts.
// TODO: Implement when adding Microsoft support.
type Provider struct {
	clientID     string
	clientSecret string
	redirectURI  string
	scopes       []string
	tenantID     string // Azure AD tenant ID (or "common" for multi-tenant)
}

// Factory creates a new Microsoft provider.
func Factory(cfg providers.ProviderConfig) (providers.Provider, error) {
	tenantID := cfg.Extra["tenant_id"]
	if tenantID == "" {
		tenantID = "common" // Multi-tenant by default
	}
	return &Provider{
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		redirectURI:  cfg.RedirectURI,
		scopes:       cfg.Scopes,
		tenantID:     tenantID,
	}, nil
}

func (p *Provider) Name() string                                             { return ProviderName }
func (p *Provider) Type() providers.ProviderType                             { return providers.ProviderTypeOIDC }
func (p *Provider) Configure(cfg providers.ProviderConfig) error             { return nil }
func (p *Provider) Validate() error                                          { return fmt.Errorf("microsoft: not implemented") }
func (p *Provider) AuthorizeURL(state, nonce string, scopes []string) string { return "" }
func (p *Provider) Exchange(ctx context.Context, code string) (*providers.TokenSet, error) {
	return nil, fmt.Errorf("microsoft: not implemented")
}
func (p *Provider) UserInfo(ctx context.Context, accessToken string) (*providers.UserProfile, error) {
	return nil, fmt.Errorf("microsoft: not implemented")
}
