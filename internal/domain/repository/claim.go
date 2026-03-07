package repository

import (
	"context"
	"time"
)

// ClaimDefinition representa un claim personalizado.
type ClaimDefinition struct {
	ID            string
	TenantID      string
	Name          string
	Description   string
	Source        string // "user_field", "static", "expression", "external"
	Value         string
	AlwaysInclude bool
	Scopes        []string
	Enabled       bool
	System        bool
	Required      bool
	ConfigData    map[string]any
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// StandardClaimConfig representa configuración de un claim OIDC estándar.
type StandardClaimConfig struct {
	ClaimName   string
	Description string
	Enabled     bool
	Scope       string
}

// ClaimsSettings representa configuración global de claims del tenant.
type ClaimsSettings struct {
	TenantID             string
	IncludeInAccessToken bool
	UseNamespacedClaims  bool
	NamespacePrefix      *string
	UpdatedAt            time.Time
}

// ClaimInput contiene los datos para crear/actualizar un claim.
type ClaimInput struct {
	Name          string
	Description   string
	Source        string
	Value         string
	AlwaysInclude bool
	Scopes        []string
	Enabled       bool
	Required      bool
	ConfigData    map[string]any
}

// ClaimsSettingsInput para actualizar settings.
type ClaimsSettingsInput struct {
	IncludeInAccessToken *bool
	UseNamespacedClaims  *bool
	NamespacePrefix      *string
}

// ScopeClaimMapping representa el mapeo de un scope a sus claims.
type ScopeClaimMapping struct {
	Scope  string
	Claims []string
}

// ClaimRepository define operaciones sobre claims.
type ClaimRepository interface {
	// Custom Claims CRUD
	Create(ctx context.Context, input ClaimInput) (*ClaimDefinition, error)
	Get(ctx context.Context, claimID string) (*ClaimDefinition, error)
	GetByName(ctx context.Context, name string) (*ClaimDefinition, error)
	List(ctx context.Context) ([]ClaimDefinition, error)
	Update(ctx context.Context, claimID string, input ClaimInput) (*ClaimDefinition, error)
	Delete(ctx context.Context, claimID string) error

	// Standard Claims Config
	GetStandardClaimsConfig(ctx context.Context) ([]StandardClaimConfig, error)
	SetStandardClaimEnabled(ctx context.Context, claimName string, enabled bool) error

	// Settings
	GetSettings(ctx context.Context) (*ClaimsSettings, error)
	UpdateSettings(ctx context.Context, input ClaimsSettingsInput) (*ClaimsSettings, error)

	// Helper para resolver
	GetEnabledClaimsForScopes(ctx context.Context, scopes []string) ([]ClaimDefinition, error)
}
