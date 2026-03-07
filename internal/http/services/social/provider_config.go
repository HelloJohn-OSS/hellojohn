package social

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// ProviderConfig describe la configuración estandarizada de un social provider.
type ProviderConfig struct {
	Name          string
	AuthURL       string
	TokenURL      string
	UserInfoURL   string // Para providers que no exponen OIDC (ej: GitHub, Facebook)
	Scopes        []string
	SupportsOIDC  bool // true = valida id_token; false = usa endpoint UserInfo
	ClaimsMapping ClaimsMapping
}

// ClaimsMapping mapea dinámicamente campos externos de la IdP a campos de HelloJohn.
type ClaimsMapping struct {
	SubField    string
	EmailField  string
	NameField   string
	AvatarField string
}

// ProviderFactory construye dinámicamente un OIDCClient condicionado por secretos del tenant.
type ProviderFactory interface {
	Build(ctx context.Context, tenantSlug, baseURL string) (OIDCClient, error)
}

// Registry administra los proveedores habilitados en el binario principal.
// Thread-safe: permite registros concurrentes y lookups simultáneos.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]ProviderFactory
}

// NewRegistry crea un registry vacío.
func NewRegistry() *Registry {
	return &Registry{factories: make(map[string]ProviderFactory)}
}

// Register agrega una factory de provider al registry.
// El nombre se normaliza a lowercase.
func (r *Registry) Register(name string, factory ProviderFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[strings.ToLower(name)] = factory
}

// Build crea un OIDCClient para el provider solicitado.
// Retorna error si el provider no está registrado.
func (r *Registry) Build(ctx context.Context, name, tenantSlug, baseURL string) (OIDCClient, error) {
	r.mu.RLock()
	factory, ok := r.factories[strings.ToLower(name)]
	r.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("provider %q not registered", name)
	}
	return factory.Build(ctx, tenantSlug, baseURL)
}

// Has verifica si un provider está registrado.
func (r *Registry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.factories[strings.ToLower(name)]
	return ok
}

// List retorna los nombres de todos los providers registrados.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	return names
}
