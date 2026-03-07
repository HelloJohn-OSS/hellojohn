// Package oidc contiene los controllers OIDC V2.
package oidc

import svc "github.com/dropDatabas3/hellojohn/internal/http/services/oidc"

// Controllers agrupa todos los controllers del dominio OIDC.
type Controllers struct {
	JWKS      *JWKSController
	Discovery *DiscoveryController
	UserInfo  *UserInfoController
}

// NewControllers crea el agregador de controllers OIDC.
func NewControllers(s svc.Services) *Controllers {
	return &Controllers{
		JWKS:      NewJWKSController(s.JWKS),
		Discovery: NewDiscoveryController(s.Discovery),
		UserInfo:  NewUserInfoController(s.UserInfo),
	}
}
