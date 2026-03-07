// Package admin contiene servicios administrativos V2.
package admin

import (
	"context"
	"fmt"

	"github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// ─── Interface ───

// ClusterService define operaciones de gestión de cluster.
type ClusterService interface {
	GetNodes(ctx context.Context) ([]admin.ClusterNodeDTO, error)
	GetStats(ctx context.Context) (*admin.ClusterStatsDTO, error)
	AddNode(ctx context.Context, req admin.AddNodeRequest) error
	RemoveNode(ctx context.Context, nodeID string) error
}

// ─── Implementation ───

type clusterService struct {
	dal store.DataAccessLayer
}

type ClusterDeps struct {
	DAL store.DataAccessLayer
}

// NewClusterService crea un nuevo ClusterService.
func NewClusterService(deps ClusterDeps) ClusterService {
	return &clusterService{
		dal: deps.DAL,
	}
}

// ─── Errors ───

var (
	ErrClusterNotEnabled = fmt.Errorf("cluster mode not enabled")
)

// ─── Methods ───

// GetNodes lista todos los nodos del cluster.
func (s *clusterService) GetNodes(ctx context.Context) ([]admin.ClusterNodeDTO, error) {
	// Verificar que el cluster esté habilitado
	clusterRepo := s.dal.Cluster()
	if clusterRepo == nil {
		return nil, ErrClusterNotEnabled
	}

	// Obtener peers del cluster
	peers, err := clusterRepo.GetPeers(ctx)
	if err != nil {
		return nil, fmt.Errorf("get peers: %w", err)
	}

	// Mapear a DTOs
	nodes := make([]admin.ClusterNodeDTO, 0, len(peers))
	for _, peer := range peers {
		nodes = append(nodes, admin.ClusterNodeDTO{
			ID:        peer.ID,
			Address:   peer.Address,
			Role:      string(peer.Role),
			State:     string(peer.State),
			JoinedAt:  peer.JoinedAt,
			LastSeen:  peer.LastSeen,
			LatencyMs: int(peer.Latency.Milliseconds()),
		})
	}

	return nodes, nil
}

// GetStats obtiene estadísticas del cluster.
func (s *clusterService) GetStats(ctx context.Context) (*admin.ClusterStatsDTO, error) {
	// Verificar que el cluster esté habilitado
	clusterRepo := s.dal.Cluster()
	if clusterRepo == nil {
		return nil, ErrClusterNotEnabled
	}

	// Obtener stats del cluster
	stats, err := clusterRepo.GetStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("get stats: %w", err)
	}

	// Mapear a DTO
	return &admin.ClusterStatsDTO{
		NodeID:       stats.NodeID,
		Role:         string(stats.Role),
		LeaderID:     stats.LeaderID,
		Term:         stats.Term,
		CommitIndex:  stats.CommitIndex,
		AppliedIndex: stats.AppliedIndex,
		NumPeers:     stats.NumPeers,
		Healthy:      stats.Healthy,
	}, nil
}

// AddNode agrega un nodo al cluster.
func (s *clusterService) AddNode(ctx context.Context, req admin.AddNodeRequest) error {
	// Verificar que el cluster esté habilitado
	clusterRepo := s.dal.Cluster()
	if clusterRepo == nil {
		return ErrClusterNotEnabled
	}

	// Validar input
	if req.ID == "" {
		return fmt.Errorf("node id is required")
	}
	if req.Address == "" {
		return fmt.Errorf("node address is required")
	}

	// Verificar que este nodo sea el líder
	isLeader, err := clusterRepo.IsLeader(ctx)
	if err != nil {
		return fmt.Errorf("check leadership: %w", err)
	}
	if !isLeader {
		// Obtener el ID del líder para redirigir
		leaderID, err := clusterRepo.GetLeaderID(ctx)
		if err != nil {
			return fmt.Errorf("get leader id: %w", err)
		}
		return fmt.Errorf("operation must be performed on leader node: %s", leaderID)
	}

	// Agregar el nodo
	if err := clusterRepo.AddPeer(ctx, req.ID, req.Address); err != nil {
		return fmt.Errorf("add peer: %w", err)
	}

	return nil
}

// RemoveNode elimina un nodo del cluster.
func (s *clusterService) RemoveNode(ctx context.Context, nodeID string) error {
	// Verificar que el cluster esté habilitado
	clusterRepo := s.dal.Cluster()
	if clusterRepo == nil {
		return ErrClusterNotEnabled
	}

	// Validar input
	if nodeID == "" {
		return fmt.Errorf("node id is required")
	}

	// Verificar que este nodo sea el líder
	isLeader, err := clusterRepo.IsLeader(ctx)
	if err != nil {
		return fmt.Errorf("check leadership: %w", err)
	}
	if !isLeader {
		// Obtener el ID del líder para redirigir
		leaderID, err := clusterRepo.GetLeaderID(ctx)
		if err != nil {
			return fmt.Errorf("get leader id: %w", err)
		}
		return fmt.Errorf("operation must be performed on leader node: %s", leaderID)
	}

	// Verificar que no se esté intentando remover a sí mismo
	stats, err := clusterRepo.GetStats(ctx)
	if err != nil {
		return fmt.Errorf("get stats: %w", err)
	}
	if stats.NodeID == nodeID {
		return fmt.Errorf("cannot remove self from cluster")
	}

	// Remover el nodo
	if err := clusterRepo.RemovePeer(ctx, nodeID); err != nil {
		return fmt.Errorf("remove peer: %w", err)
	}

	return nil
}
