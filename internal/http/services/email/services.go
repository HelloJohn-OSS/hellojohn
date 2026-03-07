package email

import (
	"time"

	controlplane "github.com/dropDatabas3/hellojohn/internal/controlplane"
	emailv2 "github.com/dropDatabas3/hellojohn/internal/email"
)

// Deps contiene las dependencias para crear los services email.
type Deps struct {
	Email          emailv2.Service
	ControlPlane   controlplane.Service
	VerifyTTL      time.Duration
	ResetTTL       time.Duration
	AutoLoginReset bool
	Issuer         TokenIssuer
}

// Services agrupa todos los services del dominio email.
type Services struct {
	Flows FlowsService
}

// NewServices crea el agregador de services email.
func NewServices(d Deps) Services {
	return Services{
		Flows: NewFlowsService(FlowsDeps{
			Email:          d.Email,
			ControlPlane:   d.ControlPlane,
			VerifyTTL:      d.VerifyTTL,
			ResetTTL:       d.ResetTTL,
			AutoLoginReset: d.AutoLoginReset,
			Issuer:         d.Issuer,
		}),
	}
}
