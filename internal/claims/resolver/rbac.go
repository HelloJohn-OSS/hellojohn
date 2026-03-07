package resolver

import (
	"context"
)

// RBACResolver resuelve la inyección de scopes/permisos y roles aplanados del usuario del ecosistema
// de bases de datos central relacional al Payloads JWT para consumir por SPAs o Cloud APIs.
type RBACResolver struct {
	IncludeRoles       bool `json:"include_roles"`
	IncludePermissions bool `json:"include_permissions"`
}

// Name devuelve "rbac".
func (r *RBACResolver) Name() string {
	return "rbac"
}

// Resolve evalúa booleanamente desde la configuración de la instancia y retorna
// colecciones en formato map string slice o simples listados para el token.
func (r *RBACResolver) Resolve(ctx context.Context, input ResolverInput) (any, error) {
	if !r.IncludeRoles && !r.IncludePermissions {
		return nil, nil // Evitamos ensuciar el JWT con objetos vacios.
	}

	result := make(map[string]any)

	if r.IncludeRoles {
		// Enforce always an array, even if empty, to preserve JWT Schema for clients
		if input.Roles != nil {
			result["roles"] = input.Roles
		} else {
			result["roles"] = []string{}
		}
	}

	if r.IncludePermissions {
		if input.Permissions != nil {
			result["permissions"] = input.Permissions
		} else {
			result["permissions"] = []string{}
		}
	}

	// Si piden ambos, mandamos el map combinado: {"roles":["admin"], "permissions":["read:users"]}
	// Si solo pidieron 1 flag, aplanamos el objeto para ahorrar Overhead Bytes a la cabecera OIDC.
	if r.IncludeRoles && !r.IncludePermissions {
		return result["roles"], nil
	}
	if r.IncludePermissions && !r.IncludeRoles {
		return result["permissions"], nil
	}

	return result, nil
}
