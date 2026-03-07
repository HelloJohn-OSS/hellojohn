// Package providers defines the multi-provider authentication system.
//
// This package enables dynamic social login provider support per-tenant configuration.
// Each tenant can enable/disable providers independently (Google, Facebook, GitHub, etc.)
//
// Architecture:
// - Provider interface: common methods all providers must implement
// - ProviderRegistry: dynamic loading based on tenant config
// - Provider implementations: one sub-package per provider
//
// Design Patterns:
// - Strategy: Each provider is a strategy for authentication
// - Factory: ProviderRegistry creates provider instances dynamically
// - Adapter: Normalize different OAuth/OIDC responses to common UserProfile
package providers

import "context"

// ProviderType indicates the authentication protocol.
type ProviderType string

const (
	ProviderTypeOIDC   ProviderType = "oidc"
	ProviderTypeOAuth2 ProviderType = "oauth2"
)

// Provider defines the interface all social login providers must implement.
type Provider interface {
	// Identity
	Name() string
	Type() ProviderType

	// Flow - OAuth/OIDC operations
	AuthorizeURL(state, nonce string, scopes []string) string
	Exchange(ctx context.Context, code string) (*TokenSet, error)
	UserInfo(ctx context.Context, accessToken string) (*UserProfile, error)

	// Configuration
	Configure(cfg ProviderConfig) error
	Validate() error
}

// ProviderConfig contains the configuration for a provider instance.
type ProviderConfig struct {
	ClientID     string
	ClientSecret string // encrypted with tenant master key
	RedirectURI  string
	Scopes       []string
	TenantSlug   string

	// Provider-specific extra config
	Extra map[string]string
}

// TokenSet contains tokens received from the provider.
type TokenSet struct {
	AccessToken  string
	RefreshToken string
	IDToken      string // OIDC only
	ExpiresIn    int
	TokenType    string
}

// UserProfile is a normalized user profile from any provider.
type UserProfile struct {
	// Core identity
	ProviderID string // Unique ID from provider (sub claim)
	Email      string
	Name       string
	GivenName  string
	FamilyName string
	Picture    string

	// Verification
	EmailVerified bool

	// Raw data for extensibility
	Raw map[string]any
}
