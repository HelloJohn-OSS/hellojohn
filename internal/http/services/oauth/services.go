// Package oauth contiene los services del dominio OAuth2/OIDC.
package oauth

import (
	"time"

	controlplane "github.com/dropDatabas3/hellojohn/internal/controlplane"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// Deps contiene las dependencias para crear los services OAuth.
type Deps struct {
	DAL          store.DataAccessLayer
	Issuer       *jwtx.Issuer
	ControlPlane controlplane.Service
	Cache        CacheClient
	CookieName   string
	AllowBearer  bool
	RefreshTTL   time.Duration // TTL for refresh tokens (default 30 days)
	// Feature flag: enforce grant compatibility by auth profile.
	ClientProfilesEnabled bool
	// Feature flag: detect refresh token reuse and revoke families.
	RefreshReuseDetectionEnabled bool
	// UI
	UIBaseURL string // Frontend base URL for OAuth consent/login page
}

// Services agrupa todos los services del dominio OAuth.
type Services struct {
	Revoke     RevokeService
	Introspect IntrospectService
	Authorize  AuthorizeService
	Token      TokenService
	Consent    ConsentService
}

// NewServices crea el agregador de services OAuth.
func NewServices(d Deps) Services {
	return Services{
		Revoke: NewRevokeService(RevokeDeps{
			DAL: d.DAL,
		}),
		Introspect: NewIntrospectService(IntrospectDeps{
			DAL:    d.DAL,
			Issuer: d.Issuer,
		}),
		Authorize: NewAuthorizeService(AuthorizeDeps{
			DAL:                   d.DAL,
			ControlPlane:          d.ControlPlane,
			Cache:                 d.Cache,
			Issuer:                d.Issuer,
			CookieName:            d.CookieName,
			AllowBearer:           d.AllowBearer,
			UIBaseURL:             d.UIBaseURL,
			ClientProfilesEnabled: d.ClientProfilesEnabled,
		}),
		Token: NewTokenService(TokenDeps{
			DAL:                          d.DAL,
			Issuer:                       d.Issuer,
			Cache:                        d.Cache,
			ControlPlane:                 d.ControlPlane,
			RefreshTTL:                   d.RefreshTTL,
			ClientProfilesEnabled:        d.ClientProfilesEnabled,
			RefreshReuseDetectionEnabled: d.RefreshReuseDetectionEnabled,
		}),
		Consent: NewConsentService(ConsentDeps{
			DAL:          d.DAL,
			Cache:        d.Cache,
			ControlPlane: d.ControlPlane,
		}),
	}
}
