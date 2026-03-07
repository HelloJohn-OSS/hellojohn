// Package health contiene los services de health check V2.
package health

// Services agrupa todos los services del dominio health.
type Services struct {
	Health HealthService
}

// NewServices crea el agregador de services health.
func NewServices(d Deps) Services {
	return Services{
		Health: NewHealthService(d),
	}
}
