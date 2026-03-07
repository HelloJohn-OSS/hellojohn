// Package admin contiene los DTOs para operaciones administrativas.
package admin

import "time"

// ─── Cluster Node DTO ───

// ClusterNodeDTO representa un nodo en el cluster Raft.
type ClusterNodeDTO struct {
	ID        string    `json:"id"`
	Address   string    `json:"address"`
	Role      string    `json:"role"`          // leader, follower, candidate
	State     string    `json:"state"`         // connected, disconnected, unknown
	JoinedAt  time.Time `json:"joined_at,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	LatencyMs int       `json:"latency_ms,omitempty"`
}

// ─── Cluster Stats DTO ───

// ClusterStatsDTO contiene estadísticas del cluster Raft.
type ClusterStatsDTO struct {
	NodeID       string `json:"node_id"`
	Role         string `json:"role"`
	LeaderID     string `json:"leader_id"`
	Term         uint64 `json:"term"`
	CommitIndex  uint64 `json:"commit_index"`
	AppliedIndex uint64 `json:"applied_index"`
	NumPeers     int    `json:"num_peers"`
	Healthy      bool   `json:"healthy"`
}

// ─── Request DTOs ───

// AddNodeRequest es la petición para agregar un nodo al cluster.
type AddNodeRequest struct {
	ID      string `json:"id" validate:"required"`
	Address string `json:"address" validate:"required"`
}

// RemoveNodeRequest es la petición para remover un nodo del cluster.
type RemoveNodeRequest struct {
	ID string `json:"id" validate:"required"`
}

// ─── Response DTOs ───

// ClusterNodesResponse es la respuesta de listar nodos.
type ClusterNodesResponse struct {
	Nodes []ClusterNodeDTO `json:"nodes"`
}

// ClusterStatsResponse es la respuesta de obtener estadísticas.
type ClusterStatsResponse struct {
	Stats *ClusterStatsDTO `json:"stats"`
}
