// Package system agrupa los services del dominio de administración del sistema.
package system

// Services agrupa todos los services del dominio system.
type Services struct {
	System SystemService
}

// NewServices crea un nuevo conjunto de services del dominio system.
func NewServices(deps SystemDeps) Services {
	return Services{System: New(deps)}
}
