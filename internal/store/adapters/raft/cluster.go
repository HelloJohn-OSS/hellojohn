// Package raft implementa ClusterRepository usando HashiCorp Raft.
package raft

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/cluster"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	clusterv2 "github.com/dropDatabas3/hellojohn/internal/store/cluster"
)

// ClusterRepo implementa repository.ClusterRepository usando cluster.Node (Raft).
type ClusterRepo struct {
	node *cluster.Node
}

// NewClusterRepo crea un ClusterRepository que wrappea un cluster.Node existente.
func NewClusterRepo(node *cluster.Node) *ClusterRepo {
	return &ClusterRepo{node: node}
}

// ─── Status ───

func (r *ClusterRepo) GetStats(ctx context.Context) (*repository.ClusterStats, error) {
	if r.node == nil {
		return nil, fmt.Errorf("cluster not initialized")
	}

	stats := r.node.Stats()

	// Parse stats to ClusterStats
	role := repository.ClusterRoleFollower
	if r.node.IsLeader() {
		role = repository.ClusterRoleLeader
	}

	term, _ := strconv.ParseUint(stats["term"], 10, 64)
	commitIndex, _ := strconv.ParseUint(stats["commit_index"], 10, 64)
	appliedIndex, _ := strconv.ParseUint(stats["applied_index"], 10, 64)
	numPeers, _ := strconv.Atoi(stats["num_peers"])

	return &repository.ClusterStats{
		NodeID:       r.node.NodeID(),
		Role:         role,
		LeaderID:     r.node.LeaderID(),
		Term:         term,
		CommitIndex:  commitIndex,
		AppliedIndex: appliedIndex,
		NumPeers:     numPeers,
		Healthy:      stats["state"] == "Leader" || stats["state"] == "Follower",
	}, nil
}

func (r *ClusterRepo) IsLeader(ctx context.Context) (bool, error) {
	if r.node == nil {
		return false, nil
	}
	return r.node.IsLeader(), nil
}

func (r *ClusterRepo) GetLeaderID(ctx context.Context) (string, error) {
	if r.node == nil {
		return "", nil
	}
	return r.node.LeaderID(), nil
}

func (r *ClusterRepo) GetPeers(ctx context.Context) ([]repository.ClusterNode, error) {
	if r.node == nil {
		return nil, nil
	}

	// Obtener la configuración real del cluster via Raft (no el mapa estático)
	config, err := r.node.GetConfiguration(ctx)
	if err != nil {
		return nil, fmt.Errorf("get configuration: %w", err)
	}

	var nodes []repository.ClusterNode
	leaderID := r.node.LeaderID()

	for _, srv := range config.Servers {
		id := string(srv.ID)
		addr := string(srv.Address)

		role := repository.ClusterRoleFollower
		// LeaderID puede venir como ID o como Address según el estado del cluster
		if id == leaderID || addr == leaderID {
			role = repository.ClusterRoleLeader
		}

		nodes = append(nodes, repository.ClusterNode{
			ID:      id,
			Address: addr,
			Role:    role,
			State:   repository.ClusterNodeHealthy,
		})
	}
	return nodes, nil
}

// ─── Replication ───

func (r *ClusterRepo) Apply(ctx context.Context, mutation repository.Mutation) (uint64, error) {
	if r.node == nil {
		return 0, fmt.Errorf("cluster not initialized")
	}
	if !r.node.IsLeader() {
		return 0, repository.ErrNotLeader
	}

	// Convertir a formato V2 y serializar una sola vez
	m := clusterv2.FromRepositoryMutation(mutation)
	data, err := json.Marshal(m)
	if err != nil {
		return 0, fmt.Errorf("marshal mutation: %w", err)
	}

	// ApplyBytes envía el JSON directamente al log Raft SIN re-envolver
	// El FSM V2 recibirá exactamente este JSON (clusterv2.Mutation)
	return r.node.ApplyBytes(ctx, data)
}

func (r *ClusterRepo) ApplyBatch(ctx context.Context, mutations []repository.Mutation) (uint64, error) {
	// Aplicar secuencialmente (Raft no tiene batch nativo)
	var lastIndex uint64
	for _, m := range mutations {
		idx, err := r.Apply(ctx, m)
		if err != nil {
			return lastIndex, err
		}
		lastIndex = idx
	}
	return lastIndex, nil
}

func (r *ClusterRepo) WaitForApply(ctx context.Context, targetIndex uint64, timeout time.Duration) error {
	// Implementación simple: poll stats
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		stats, err := r.GetStats(ctx)
		if err != nil {
			return err
		}
		if stats.AppliedIndex >= targetIndex {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return fmt.Errorf("timeout waiting for apply index %d", targetIndex)
}

// ─── Membership ───

func (r *ClusterRepo) AddPeer(ctx context.Context, id, address string) error {
	if r.node == nil {
		return fmt.Errorf("cluster not initialized")
	}
	if !r.node.IsLeader() {
		return repository.ErrNotLeader
	}
	return r.node.AddVoter(ctx, id, address)
}

func (r *ClusterRepo) RemovePeer(ctx context.Context, id string) error {
	if r.node == nil {
		return fmt.Errorf("cluster not initialized")
	}
	if !r.node.IsLeader() {
		return repository.ErrNotLeader
	}
	return r.node.RemoveServer(ctx, id)
}

// ─── Health ───

func (r *ClusterRepo) Ping(ctx context.Context) error {
	if r.node == nil {
		return fmt.Errorf("cluster not initialized")
	}
	// Si tenemos stats, está vivo
	_, err := r.GetStats(ctx)
	return err
}

func (r *ClusterRepo) Close() error {
	if r.node == nil {
		return nil
	}
	return r.node.Close()
}

// Ensure ClusterRepo implements ClusterRepository
var _ repository.ClusterRepository = (*ClusterRepo)(nil)
