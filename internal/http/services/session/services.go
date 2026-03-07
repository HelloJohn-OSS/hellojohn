// Package session contiene los services del dominio session.
package session

import (
	"time"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/session"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
)

// Deps contiene las dependencias para crear los services session.
type Deps struct {
	Cache       Cache
	LoginConfig dto.LoginConfig
	Issuer      *jwtx.Issuer
	TokenTTL    time.Duration
}

// Services agrupa todos los services del dominio session.
type Services struct {
	Login LoginService
	Token SessionTokenService
}

// NewServices crea el agregador de services session.
func NewServices(d Deps) Services {
	return Services{
		Login: NewLoginService(LoginDeps{
			Cache:  d.Cache,
			Config: d.LoginConfig,
		}),
		Token: NewSessionTokenService(SessionTokenDeps{
			Cache:    d.Cache,
			Issuer:   d.Issuer,
			TokenTTL: d.TokenTTL,
		}),
	}
}
