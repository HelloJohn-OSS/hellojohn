// Package providers - Provider Registry for dynamic provider loading
package providers

import (
	"context"
	"fmt"
	"sync"
)

// ProviderFactory creates a new provider instance.
type ProviderFactory func(cfg ProviderConfig) (Provider, error)

// Registry manages provider factories and instances.
type Registry struct {
	mu        sync.RWMutex
	factories map[string]ProviderFactory
	cache     map[string]Provider // key: "tenant:provider"
}

// NewRegistry creates a new provider registry.
func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[string]ProviderFactory),
		cache:     make(map[string]Provider),
	}
}

// RegisterFactory registers a factory for a provider type.
// This should be called at startup for each supported provider.
func (r *Registry) RegisterFactory(name string, factory ProviderFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[name] = factory
}

// GetProvider returns a provider for the given tenant and provider name.
// It caches instances per tenant to avoid repeated initialization.
func (r *Registry) GetProvider(ctx context.Context, tenantSlug, providerName string, cfg ProviderConfig) (Provider, error) {
	key := fmt.Sprintf("%s:%s", tenantSlug, providerName)

	r.mu.RLock()
	if p, ok := r.cache[key]; ok {
		r.mu.RUnlock()
		return p, nil
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock
	if p, ok := r.cache[key]; ok {
		return p, nil
	}

	factory, ok := r.factories[providerName]
	if !ok {
		return nil, fmt.Errorf("provider not registered: %s", providerName)
	}

	provider, err := factory(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider %s: %w", providerName, err)
	}

	r.cache[key] = provider
	return provider, nil
}

// AvailableProviders returns the list of registered provider names.
func (r *Registry) AvailableProviders() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	return names
}

// InvalidateCache removes cached providers for a tenant.
// Call this when tenant config changes.
func (r *Registry) InvalidateCache(tenantSlug string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for key := range r.cache {
		// Check if key starts with tenant slug
		if len(key) > len(tenantSlug) && key[:len(tenantSlug)+1] == tenantSlug+":" {
			delete(r.cache, key)
		}
	}
}
