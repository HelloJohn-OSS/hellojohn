// Package session contains controllers for session-related endpoints.
package session

import (
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/session"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/session"
)

// ControllerDeps contains additional dependencies for controllers.
type ControllerDeps struct {
	LoginConfig dto.LoginConfig
}

// Controllers agrupa todos los controllers del dominio session.
type Controllers struct {
	Login *LoginController
	Token *SessionTokenController
}

// NewControllers creates the session controllers aggregator.
func NewControllers(s svc.Services, deps ControllerDeps) *Controllers {
	return &Controllers{
		Login: NewLoginController(s.Login, deps.LoginConfig),
		Token: NewSessionTokenController(s.Token, deps.LoginConfig),
	}
}
