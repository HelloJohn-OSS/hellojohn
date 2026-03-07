package resolver

import (
	"context"
)

// StaticResolver implementa el inyector más básico.
// Su propósito es devolver un valor preconfigurado y constante (ej: un tenant string,
// un valor booleano o cualquier primitivo JSON hardcodeado) para un Custom Claim.
type StaticResolver struct {
	Value any `json:"value"` // Puede ser un bool, float64, map, array, string
}

// Name devuelve el tipo cardinal de esta instancia.
func (s *StaticResolver) Name() string {
	return "static"
}

// Resolve ejecuta la aserción y retorna directamente el Value hardcodeado sin procesar contextos.
func (s *StaticResolver) Resolve(ctx context.Context, input ResolverInput) (any, error) {
	return s.Value, nil
}
