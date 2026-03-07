// Package cluster provee infraestructura Raft neutral (sin dependencias de controlplane).
// Los tipos V1 legacy están en internal/cluster/v1.
package cluster

// MutationType define el catálogo de operaciones replicadas.
// Esta es la versión neutral que no depende de controlplane.
type MutationType string

// Mutation representa una operación a replicar por Raft.
// Esta es la versión mínima para infra sin acoplar a CP v1.
// El payload es JSON crudo pre-serializado.
type Mutation struct {
	Type       MutationType `json:"type"`
	TenantSlug string       `json:"tenantSlug"`
	Key        string       `json:"key,omitempty"` // clientID, scopeName, etc.
	TsUnix     int64        `json:"tsUnix"`
	Payload    []byte       `json:"payload"` // JSON crudo del DTO
}
