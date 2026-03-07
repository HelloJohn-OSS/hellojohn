// Package noop contiene el adapter noop para ClusterRepository.
package noop

import (
	"context"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// noopCluster implementa ClusterRepository como single-node (sin replicación).
// Siempre es leader y Apply es un noop que retorna OK.
type noopCluster struct {
	nodeID string
}

// NewClusterRepository crea un ClusterRepository noop (single-node).
func NewClusterRepository(nodeID string) repository.ClusterRepository {
	if nodeID == "" {
		nodeID = "single"
	}
	return &noopCluster{nodeID: nodeID}
}

func (c *noopCluster) GetStats(ctx context.Context) (*repository.ClusterStats, error) {
	return &repository.ClusterStats{
		NodeID:   c.nodeID,
		Role:     repository.ClusterRoleLeader,
		LeaderID: c.nodeID,
		NumPeers: 1,
		Healthy:  true,
	}, nil
}

func (c *noopCluster) IsLeader(ctx context.Context) (bool, error) {
	return true, nil
}

func (c *noopCluster) GetLeaderID(ctx context.Context) (string, error) {
	return c.nodeID, nil
}

func (c *noopCluster) GetPeers(ctx context.Context) ([]repository.ClusterNode, error) {
	return []repository.ClusterNode{
		{
			ID:       c.nodeID,
			Role:     repository.ClusterRoleLeader,
			State:    repository.ClusterNodeHealthy,
			JoinedAt: time.Now(),
			LastSeen: time.Now(),
		},
	}, nil
}

func (c *noopCluster) Apply(ctx context.Context, mutation repository.Mutation) (uint64, error) {
	// Single-node: no hay replicación, siempre OK
	// Retornamos index 0 (no hay log real)
	return 0, nil
}

func (c *noopCluster) ApplyBatch(ctx context.Context, mutations []repository.Mutation) (uint64, error) {
	return 0, nil
}

func (c *noopCluster) WaitForApply(ctx context.Context, targetIndex uint64, timeout time.Duration) error {
	return nil
}

func (c *noopCluster) AddPeer(ctx context.Context, id, address string) error {
	// Noop: no soporta multi-node
	return nil
}

func (c *noopCluster) RemovePeer(ctx context.Context, id string) error {
	return nil
}

func (c *noopCluster) Ping(ctx context.Context) error {
	return nil
}

func (c *noopCluster) Close() error {
	return nil
}
