package resolver

import (
	"context"
)

// ResolverInput representa el contexto enriquecido necesario para que
// cualquier Resolver (Estático, Webhook, Expresión CEL) pueda calcular
// dinámicamente el valor final de un Custom Claim antes de la emisión del JWT.
type ResolverInput struct {
	UserID      string
	TenantID    string
	Email       string
	Scopes      []string       // Scopes solicitados y aceptados en el flujo OAuth actual
	ClientID    string         // Aplicación o Cliente OIDC consumiendo
	Roles       []string       // Roles duros (RBAC) asociados al usuario
	Permissions []string       // Permisos granulares desanidados del usuario
	UserMeta    map[string]any // Metadata JSONB arbitraria extraída de app_user
}

// Resolver define el contrato universal para inyectores de Claims.
type Resolver interface {
	// Name devuelve la cardinalidad o tipo del resolutor (ej: "static", "rbac", "webhook")
	Name() string

	// Resolve ejecuta la aserción y retorna el valor (string, bool, numérico, objeto)
	// que formará parte estructural del JWT del Tenant.
	Resolve(ctx context.Context, input ResolverInput) (any, error)
}
