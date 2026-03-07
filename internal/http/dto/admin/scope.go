// Package admin contiene DTOs para endpoints administrativos.
package admin

// ScopeRequest representa la entrada para crear/actualizar un scope.
type ScopeRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	DisplayName string   `json:"display_name,omitempty"`
	Claims      []string `json:"claims,omitempty"`
	DependsOn   string   `json:"depends_on,omitempty"`
	System      bool     `json:"system,omitempty"`
}

// ScopeResponse representa un scope en la respuesta.
type ScopeResponse struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	DisplayName string   `json:"display_name,omitempty"`
	Claims      []string `json:"claims,omitempty"`
	DependsOn   string   `json:"depends_on,omitempty"`
	System      bool     `json:"system,omitempty"`
	CreatedAt   string   `json:"created_at,omitempty"`
	UpdatedAt   string   `json:"updated_at,omitempty"`
}

// ScopeListResponse es una lista de scopes.
type ScopeListResponse []ScopeResponse
