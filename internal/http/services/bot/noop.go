package bot

import "context"

// NoopService es una implementación no-operante para tests y ambientes sin config.
// Siempre permite el acceso sin llamar a ningún servicio externo.
type NoopService struct{}

// NewNoop crea una instancia del NoopService.
func NewNoop() BotProtectionService { return &NoopService{} }

// Validate siempre retorna nil (sin-op).
func (n *NoopService) Validate(_ context.Context, _ ValidateRequest) error { return nil }

// ResolveConfig retorna siempre disabled.
func (n *NoopService) ResolveConfig(_ context.Context, _ string) (*ResolvedConfig, error) {
	return &ResolvedConfig{Enabled: false}, nil
}
