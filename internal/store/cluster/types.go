// Package clusterv2 implementa tipos y FSM para cluster V2 desacoplado de controlplane/v1.
// El FSM es determinístico: no genera IDs ni timestamps, solo aplica payloads pre-construidos.
package clusterv2

import (
	"encoding/json"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// MutationType define el catálogo de operaciones replicadas (compatibles con repository.MutationType).
type MutationType string

const (
	// Clients
	MutationClientCreate MutationType = "client.create"
	MutationClientUpdate MutationType = "client.update"
	MutationClientDelete MutationType = "client.delete"

	// Tenants
	MutationTenantCreate   MutationType = "tenant.create"
	MutationTenantUpdate   MutationType = "tenant.update"
	MutationTenantDelete   MutationType = "tenant.delete"
	MutationSettingsUpdate MutationType = "settings.update"

	// Scopes
	MutationScopeCreate MutationType = "scope.create"
	MutationScopeDelete MutationType = "scope.delete"

	// Keys
	MutationKeyRotate MutationType = "key.rotate"
)

// Mutation representa una operación a replicar por Raft.
// Payload contiene JSON pre-construido (leader ya validó y serializó).
type Mutation struct {
	Type       MutationType `json:"type"`
	TenantSlug string       `json:"tenantSlug"`
	Key        string       `json:"key,omitempty"` // clientID, scopeName, etc.
	TsUnix     int64        `json:"tsUnix"`
	Payload    []byte       `json:"payload"` // JSON crudo del DTO
}

// FromRepositoryMutation convierte repository.Mutation a Mutation V2.
func FromRepositoryMutation(m repository.Mutation) Mutation {
	return Mutation{
		Type:       MutationType(m.Type),
		TenantSlug: m.TenantID, // TenantID en repo = TenantSlug aquí
		Key:        m.Key,
		TsUnix:     m.Timestamp.Unix(),
		Payload:    m.Payload,
	}
}

// ToRepositoryMutation convierte Mutation V2 a repository.Mutation.
func (m Mutation) ToRepositoryMutation() repository.Mutation {
	return repository.Mutation{
		Type:      repository.MutationType(m.Type),
		TenantID:  m.TenantSlug,
		Key:       m.Key,
		Payload:   m.Payload,
		Timestamp: time.Unix(m.TsUnix, 0),
	}
}

// ─── DTOs de payload (todos los datos ya vienen "finales") ───

// ClientPayload para create/update de clients.
// Secret ya viene cifrado o vacío (confidential vs public).
type ClientPayload struct {
	ClientID                 string   `json:"clientId"`
	Name                     string   `json:"name"`
	Type                     string   `json:"type"` // "public", "confidential"
	AuthProfile              string   `json:"authProfile,omitempty"`
	Secret                   string   `json:"secret,omitempty"`
	RedirectURIs             []string `json:"redirectUris"`
	AllowedOrigins           []string `json:"allowedOrigins,omitempty"`
	Providers                []string `json:"providers,omitempty"`
	Scopes                   []string `json:"scopes,omitempty"`
	RequireEmailVerification bool     `json:"requireEmailVerification,omitempty"`
	ResetPasswordURL         string   `json:"resetPasswordUrl,omitempty"`
	VerifyEmailURL           string   `json:"verifyEmailUrl,omitempty"`
	GrantTypes               []string `json:"grantTypes,omitempty"`
	AccessTokenTTL           int      `json:"accessTokenTTL,omitempty"`
	RefreshTokenTTL          int      `json:"refreshTokenTTL,omitempty"`
	IDTokenTTL               int      `json:"idTokenTTL,omitempty"`
	PostLogoutURIs           []string `json:"postLogoutURIs,omitempty"`
	Description              string   `json:"description,omitempty"`
}

// DeletePayload para delete genérico (clientID, scopeName, etc).
type DeletePayload struct {
	ID string `json:"id"`
}

// TenantPayload para create/update de tenants.
type TenantPayload struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Slug      string          `json:"slug"`
	Settings  json.RawMessage `json:"settings,omitempty"` // TenantSettings serializado
	CreatedAt int64           `json:"createdAt,omitempty"`
	UpdatedAt int64           `json:"updatedAt,omitempty"`
}

// SettingsPayload para actualizar solo settings de un tenant.
type SettingsPayload struct {
	Settings json.RawMessage `json:"settings"` // TenantSettings ya con secrets cifrados
}

// ScopePayload para create scope.
type ScopePayload struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	DisplayName string   `json:"display_name,omitempty"`
	Claims      []string `json:"claims,omitempty"`
	DependsOn   string   `json:"depends_on,omitempty"`
	System      bool     `json:"system,omitempty"`
}

// KeyRotatePayload para replicar rotación de keys.
// Los JSONs de active.json y retiring.json ya vienen pre-generados por leader.
type KeyRotatePayload struct {
	ActiveJSON   string `json:"activeJson"`
	RetiringJSON string `json:"retiringJson,omitempty"`
	GraceSeconds int64  `json:"graceSeconds,omitempty"`
}
