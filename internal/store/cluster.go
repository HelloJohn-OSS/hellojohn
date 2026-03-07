package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// ─── Cluster Hooks ───
// Funciones helper para aplicar mutaciones al cluster después de operaciones FS.

// ClusterHook encapsula la lógica de replicación de cluster para operaciones de control plane.
type ClusterHook struct {
	cluster repository.ClusterRepository
	mode    OperationalMode
}

// NewClusterHook crea un hook de cluster.
// Si cluster es nil, todos los métodos son noop.
func NewClusterHook(cluster repository.ClusterRepository, mode OperationalMode) *ClusterHook {
	return &ClusterHook{cluster: cluster, mode: mode}
}

// RequireLeaderForMutation verifica si el nodo es leader antes de permitir una mutación.
// Retorna ErrNotLeader si el cluster está configurado y este nodo no es leader.
// Si no hay cluster configurado, retorna nil (single-node mode).
func (h *ClusterHook) RequireLeaderForMutation(ctx context.Context) error {
	// Sin cluster: modo single-node, siempre OK
	if h.cluster == nil {
		return nil
	}

	// Con DB global: la sincronización se hace por DB, no por cluster
	if h.mode == ModeFSGlobalDB || h.mode == ModeFullDB {
		return nil
	}

	// Verificar que somos leader
	isLeader, err := h.cluster.IsLeader(ctx)
	if err != nil {
		return err
	}
	if !isLeader {
		return ErrNotLeader
	}
	return nil
}

// Apply aplica una mutación al cluster después de una operación exitosa.
// Si no hay cluster configurado, es noop.
// Retorna el índice del log (0 si es noop).
func (h *ClusterHook) Apply(ctx context.Context, mutation repository.Mutation) (uint64, error) {
	if h.cluster == nil {
		return 0, nil
	}

	// Con DB global: skip cluster replication (DB es el source of truth)
	if h.mode == ModeFSGlobalDB || h.mode == ModeFullDB {
		return 0, nil
	}

	return h.cluster.Apply(ctx, mutation)
}

// ─── Mutation Helpers ───

// NewClientMutation crea una mutación para operaciones de client.
func NewClientMutation(mutType repository.MutationType, tenantID, clientID string, payload any) repository.Mutation {
	data, _ := json.Marshal(payload)
	return repository.Mutation{
		Type:      mutType,
		TenantID:  tenantID,
		Key:       clientID,
		Payload:   data,
		Timestamp: time.Now(),
	}
}

// NewScopeMutation crea una mutación para operaciones de scope.
func NewScopeMutation(mutType repository.MutationType, tenantID, scopeName string, payload any) repository.Mutation {
	data, _ := json.Marshal(payload)
	return repository.Mutation{
		Type:      mutType,
		TenantID:  tenantID,
		Key:       scopeName,
		Payload:   data,
		Timestamp: time.Now(),
	}
}

// NewTenantMutation crea una mutación para operaciones de tenant.
func NewTenantMutation(mutType repository.MutationType, tenantID string, payload any) repository.Mutation {
	data, _ := json.Marshal(payload)
	return repository.Mutation{
		Type:      mutType,
		TenantID:  tenantID,
		Key:       tenantID,
		Payload:   data,
		Timestamp: time.Now(),
	}
}
