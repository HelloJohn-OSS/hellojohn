package claims

import (
	"context"
	"fmt"

	"github.com/dropDatabas3/hellojohn/internal/claims/resolver"
)

// ClaimConfig define un contrato de Claim registrado en el Tenant Settings.
type ClaimConfig struct {
	ClaimName    string         `json:"claim_name"`
	ResolverType string         `json:"resolver_type"` // "rbac", "webhook_api", "expression", "static", "user_attribute"
	Required     bool           `json:"required"`
	Scopes       []string       `json:"scopes"` // Array de gatillos OAuth2 (ej. "profile")
	ConfigData   map[string]any `json:"config"` // Parametrización dinámica del resolver
}

// ClaimsHook es el orquestador maestro ("Interceptor") a inyectarse en el generador JWT.
type ClaimsHook struct {
	configs   []ClaimConfig
	resolvers map[string]resolver.Resolver
}

// NewClaimsHook instancia la factoría de delegación OIDC.
func NewClaimsHook(configs []ClaimConfig, resolvers map[string]resolver.Resolver) *ClaimsHook {
	return &ClaimsHook{
		configs:   configs,
		resolvers: resolvers,
	}
}

// ResolveAll itera y ejecuta los motores de resolución (Estáticos, Webhooks, CEL).
// Detiene el ciclo logístico y corrompe el Single Sign-On si el Claim Config requerido falla ruidosamente.
func (h *ClaimsHook) ResolveAll(ctx context.Context, input resolver.ResolverInput) (map[string]any, error) {
	out := make(map[string]any)

	// Optimización O(1) para lookups de Scopes Solicitados por el Client / Usuario.
	reqScopes := make(map[string]bool)
	for _, s := range input.Scopes {
		reqScopes[s] = true
	}

	for _, cfg := range h.configs {
		// Evaluacion de Gatillo Condicional.
		// Si el Claim no impone Scopes (vacio), se inyectará siempre.
		shouldRun := len(cfg.Scopes) == 0
		for _, requiredScope := range cfg.Scopes {
			if reqScopes[requiredScope] {
				shouldRun = true
				break
			}
		}

		if !shouldRun {
			continue // El usuario no requirió el scope OAuth2 atado a este Claim
		}

		rsv, ok := h.resolvers[cfg.ResolverType]
		if !ok {
			// Si falla silenciosamente porque no existe el builder, pero es Requerido, falla login.
			if cfg.Required {
				return nil, fmt.Errorf("hard-failure: required resolver engine '%s' not found or disabled in control plane", cfg.ResolverType)
			}
			continue
		}

		// Delegar ejecución de la magia al Motor Interno
		val, err := rsv.Resolve(ctx, input)
		if err != nil {
			if cfg.Required {
				return nil, fmt.Errorf("failed required claim resolution '%s': %w", cfg.ClaimName, err)
			}
			continue // Resiliencia Fail-Open: Se omite pero el JWT se genera (ej: webhook down timeout)
		}

		// Protección OIDC: Flatten & Namespace Override
		finalKey := EnforceNamespace(cfg.ClaimName)

		// Si es "nil" un resolver válido porque la BD/Attr no lo tiene llenado. (UserAttr nil fail-open)
		if val != nil {
			out[finalKey] = val
		}
	}

	return out, nil
}
