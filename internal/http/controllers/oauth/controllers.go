// Package oauth contains controllers for OAuth2/OIDC endpoints.
package oauth

import svc "github.com/dropDatabas3/hellojohn/internal/http/services/oauth"

// ControllerDeps contains additional dependencies for controllers.
type ControllerDeps struct {
	ClientAuth ClientAuthenticator // Optional: for /introspect client auth
}

// Controllers agrupa todos los controllers del dominio OAuth.
type Controllers struct {
	Authorize  *AuthorizeController
	Token      *TokenController
	Introspect *IntrospectController
	Revoke     *RevokeController
	Consent    *ConsentController
}

// NewControllers creates the OAuth controllers aggregator.
func NewControllers(s svc.Services, deps ControllerDeps) *Controllers {
	return &Controllers{
		Authorize:  NewAuthorizeController(s.Authorize),
		Token:      NewTokenController(s.Token),
		Revoke:     NewRevokeController(s.Revoke),
		Introspect: NewIntrospectController(s.Introspect, deps.ClientAuth),
		Consent:    NewConsentController(s.Consent),
	}
}
