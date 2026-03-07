package social

import (
	"context"
	"fmt"
)

// GitLabFactory resolves the built-in gitlab provider through generic OIDC alias configuration.
// Operators configure gitlab in tenant settings under socialProviders.customOidcProviders alias "gitlab".
type GitLabFactory struct {
	TenantProvider TenantProvider
	GenericOIDC    GenericOIDCResolver
}

func (f *GitLabFactory) Build(ctx context.Context, tenantSlug, baseURL string) (OIDCClient, error) {
	resolver := f.GenericOIDC
	if resolver == nil {
		if f.TenantProvider == nil {
			return nil, fmt.Errorf("tenant provider not configured")
		}
		resolver = &GenericOIDCFactory{TenantProvider: f.TenantProvider}
	}

	return resolver.BuildForAlias(ctx, tenantSlug, baseURL, "gitlab")
}
