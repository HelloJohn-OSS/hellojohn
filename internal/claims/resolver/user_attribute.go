package resolver

import (
	"context"
	"strings"
)

// UserAttributeResolver lee propiedades directas del perfíl del usuario (ResolverInput).
// Sirve para mapear Claims OIDC predecibles como "email", "sub" (UserID), etc,
// o rebuscar sub-campos dentro del diccionario dinámico `UserMeta`.
type UserAttributeResolver struct {
	Field string `json:"field"` // e.g: "email", "user_id", "metadata.company", "metadata.age"
}

func (u *UserAttributeResolver) Name() string {
	return "user_attribute"
}

func (u *UserAttributeResolver) Resolve(ctx context.Context, input ResolverInput) (any, error) {
	if u.Field == "" {
		return nil, nil // Ignora amablemente si está mal configurado.
	}

	// 1. Mapeos primarios al struct nativo de HelloJohn.
	switch u.Field {
	case "email":
		return input.Email, nil
	case "user_id", "sub":
		return input.UserID, nil
	case "tenant_id":
		return input.TenantID, nil
	case "client_id":
		return input.ClientID, nil
	}

	// 2. Extracción profunda desde Metadata (JSONB).
	// Si el usuario configuró "metadata.organization.id", debemos partir el string y bucear.
	if strings.HasPrefix(u.Field, "metadata.") {
		if input.UserMeta == nil {
			return nil, nil // No hay metadata en el usuario, no panicamos. Devolvemos Nil.
		}

		path := strings.TrimPrefix(u.Field, "metadata.")
		keys := strings.Split(path, ".")

		return extractNestedValue(input.UserMeta, keys)
	}

	// Campo no soportado o inexistente. (Silent ignore).
	return nil, nil
}

// extractNestedValue navega un árbol de mapas de Go a través de []keys
func extractNestedValue(data map[string]any, keys []string) (any, error) {
	if len(keys) == 0 {
		return nil, nil
	}

	currentKey := keys[0]
	val, ok := data[currentKey]
	if !ok {
		return nil, nil // Path dead-end
	}

	// Última llave en el path, hemos llegado al value
	if len(keys) == 1 {
		return val, nil
	}

	// Si no es la última llave, el value actual DEBE ser un sub-map map[string]any
	subMap, isMap := val.(map[string]any)
	if !isMap {
		return nil, nil // Type mismatch, the user expected an object but it's a primitive.
	}

	// Recursión
	return extractNestedValue(subMap, keys[1:])
}
