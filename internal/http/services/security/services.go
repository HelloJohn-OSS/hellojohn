// Package security contiene los services del dominio security.
package security

import (
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/security"
)

// Deps contiene las dependencias para crear los services security.
type Deps struct {
	CSRFConfig dto.CSRFConfig
}

// Services agrupa todos los services del dominio security.
type Services struct {
	CSRF CSRFService
}

// NewServices crea el agregador de services security.
func NewServices(d Deps) Services {
	return Services{
		CSRF: NewCSRFService(CSRFDeps{
			Config: d.CSRFConfig,
		}),
	}
}
