// Package health contiene los controllers de health check V2.
package health

import svc "github.com/dropDatabas3/hellojohn/internal/http/services/health"

// Controllers agrupa todos los controllers del dominio health.
type Controllers struct {
	Health *HealthController
}

// NewControllers crea el agregador de controllers health.
func NewControllers(s svc.Services) *Controllers {
	return &Controllers{
		Health: NewHealthController(s.Health),
	}
}
