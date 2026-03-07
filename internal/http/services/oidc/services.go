// Package oidc contiene los services OIDC V2.
package oidc

import (
	controlplane "github.com/dropDatabas3/hellojohn/internal/controlplane"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// Deps contiene las dependencias para crear los services OIDC.
type Deps struct {
	JWKSCache    *jwtx.JWKSCache
	BaseIssuer   string
	ControlPlane controlplane.Service
	Issuer       *jwtx.Issuer
	DAL          store.DataAccessLayer
}

// Services agrupa todos los services del dominio OIDC.
type Services struct {
	JWKS      JWKSService
	Discovery DiscoveryService
	UserInfo  UserInfoService
}

// NewServices crea el agregador de services OIDC.
func NewServices(d Deps) Services {
	return Services{
		JWKS:      NewJWKSService(d.JWKSCache),
		Discovery: NewDiscoveryService(d.BaseIssuer, d.ControlPlane),
		UserInfo: NewUserInfoService(UserInfoDeps{
			Issuer:       d.Issuer,
			ControlPlane: d.ControlPlane,
			DAL:          d.DAL,
		}),
	}
}
