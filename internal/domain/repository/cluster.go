package repository

import (
	"context"
	"time"
)

// ClusterNode representa un nodo del cluster.
type ClusterNode struct {
	ID       string
	Address  string
	Role     ClusterRole
	State    ClusterNodeState
	JoinedAt time.Time
	LastSeen time.Time
	Latency  time.Duration
}

// ClusterRole indica el rol de un nodo.
type ClusterRole string

const (
	ClusterRoleLeader    ClusterRole = "leader"
	ClusterRoleFollower  ClusterRole = "follower"
	ClusterRoleCandidate ClusterRole = "candidate"
)

// ClusterNodeState indica el estado de un nodo.
type ClusterNodeState string

const (
	ClusterNodeHealthy     ClusterNodeState = "healthy"
	ClusterNodeDegraded    ClusterNodeState = "degraded"
	ClusterNodeUnreachable ClusterNodeState = "unreachable"
)

// ClusterStats contiene estadísticas del cluster.
type ClusterStats struct {
	NodeID       string
	Role         ClusterRole
	LeaderID     string
	Term         uint64
	CommitIndex  uint64
	AppliedIndex uint64
	NumPeers     int
	Healthy      bool
}

// MutationType indica el tipo de mutación a replicar.
type MutationType string

const (
	MutationTenantCreate   MutationType = "tenant.create"
	MutationTenantUpdate   MutationType = "tenant.update"
	MutationTenantDelete   MutationType = "tenant.delete"
	MutationClientCreate   MutationType = "client.create"
	MutationClientUpdate   MutationType = "client.update"
	MutationClientDelete   MutationType = "client.delete"
	MutationScopeCreate    MutationType = "scope.create"
	MutationScopeDelete    MutationType = "scope.delete"
	MutationKeyRotate      MutationType = "key.rotate"
	MutationSettingsUpdate MutationType = "settings.update"
)

// Mutation representa una operación a replicar en el cluster.
type Mutation struct {
	Type      MutationType
	TenantID  string
	Key       string // client_id, scope_name, etc.
	Payload   []byte // JSON serializado
	Timestamp time.Time
}

// ClusterRepository define operaciones de cluster/replicación.
// Abstrae Raft u otros protocolos de consenso.
type ClusterRepository interface {
	// ─── Status ───

	// GetStats obtiene estadísticas del cluster.
	GetStats(ctx context.Context) (*ClusterStats, error)

	// IsLeader indica si este nodo es el líder.
	IsLeader(ctx context.Context) (bool, error)

	// GetLeaderID obtiene el ID del líder actual.
	GetLeaderID(ctx context.Context) (string, error)

	// GetPeers lista todos los nodos del cluster.
	GetPeers(ctx context.Context) ([]ClusterNode, error)

	// ─── Replication ───

	// Apply aplica una mutación al cluster.
	// Solo el líder puede aplicar; followers retornan ErrNotLeader.
	// Retorna el índice del log para usar con WaitForApply.
	Apply(ctx context.Context, mutation Mutation) (index uint64, err error)

	// ApplyBatch aplica múltiples mutaciones secuencialmente.
	// Retorna el último índice aplicado.
	ApplyBatch(ctx context.Context, mutations []Mutation) (lastIndex uint64, err error)

	// WaitForApply espera a que una mutación se replique.
	// Retorna cuando commitIndex >= targetIndex.
	WaitForApply(ctx context.Context, targetIndex uint64, timeout time.Duration) error

	// ─── Membership ───

	// AddPeer agrega un nodo al cluster.
	AddPeer(ctx context.Context, id, address string) error

	// RemovePeer elimina un nodo del cluster.
	RemovePeer(ctx context.Context, id string) error

	// ─── Health ───

	// Ping verifica conectividad con el cluster.
	Ping(ctx context.Context) error

	// Close cierra conexiones del cluster.
	Close() error
}
