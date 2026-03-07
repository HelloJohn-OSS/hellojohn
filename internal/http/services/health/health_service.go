// Package health contiene el service para health checks.
package health

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	controlplane "github.com/dropDatabas3/hellojohn/internal/controlplane"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/health"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	jwtv5 "github.com/golang-jwt/jwt/v5"
)

// HealthService define las operaciones de health check.
type HealthService interface {
	Check(ctx context.Context) dto.HealthResponse
}

// ClusterChecker abstrae las operaciones de cluster para health.
type ClusterChecker interface {
	IsLeader() bool
	LeaderID() string
	Stats() map[string]any
	KnownPeers() int
}

// TenantPoolStats abstrae las estadísticas de pools de tenant.
type TenantPoolStats interface {
	Stats() map[string]PoolStat
}

// PoolStat representa estadísticas de un pool.
type PoolStat struct {
	Acquired int32
	Idle     int32
	Total    int32
}

// Deps contiene las dependencias inyectables para el health service.
type Deps struct {
	ControlPlane    controlplane.Service
	Issuer          *jwtx.Issuer
	DBCheck         func(ctx context.Context) error // DB ping check function
	RedisCheck      func(ctx context.Context) error
	ClusterChecker  ClusterChecker
	TenantPools     TenantPoolStats
	FSDegraded      *atomic.Bool
	LeaderRedirects []string
	ServiceVersion  string // For /health response
	ServiceCommit   string // For /health response
}

type healthService struct {
	deps Deps
}

// NewHealthService crea un nuevo service de health check.
func NewHealthService(deps Deps) HealthService {
	return &healthService{deps: deps}
}

const componentHealth = "health"

func (s *healthService) Check(ctx context.Context) dto.HealthResponse {
	log := logger.From(ctx).With(
		logger.Layer("service"),
		logger.Component(componentHealth),
		logger.Op("Check"),
	)

	response := dto.HealthResponse{
		Components: make(map[string]dto.HealthStatus),
		Timestamp:  time.Now().UTC(),
	}

	// Service metadata (injected via deps)
	if s.deps.ServiceVersion != "" {
		response.Version = s.deps.ServiceVersion
	}
	if s.deps.ServiceCommit != "" {
		response.Commit = s.deps.ServiceCommit
	}
	if s.deps.Issuer != nil {
		if kid, err := s.deps.Issuer.ActiveKID(); err == nil && kid != "" {
			response.ActiveKeyID = kid
		}
	}

	hasErrors := false
	hasCriticalErrors := false

	// 1) Control-plane (crítico)
	if s.deps.ControlPlane != nil {
		if _, err := s.deps.ControlPlane.ListTenants(ctx); err != nil {
			response.Components["control_plane"] = dto.HealthStatus{
				Status:  "error",
				Message: fmt.Sprintf("unavailable: %v", err),
			}
			hasCriticalErrors = true
			log.Error("control_plane unavailable", logger.Err(err))
		} else {
			response.Components["control_plane"] = dto.HealthStatus{Status: "ok"}
		}
	} else {
		response.Components["control_plane"] = dto.HealthStatus{
			Status:  "error",
			Message: "provider not initialized",
		}
		hasCriticalErrors = true
	}

	// 2) JWT Keystore (crítico)
	if s.deps.Issuer != nil {
		keystoreErr := s.checkKeystore(ctx)
		if keystoreErr != nil {
			response.Components["keystore"] = dto.HealthStatus{
				Status:  "error",
				Message: keystoreErr.Error(),
			}
			hasCriticalErrors = true
			log.Error("keystore check failed", logger.Err(keystoreErr))
		} else {
			response.Components["keystore"] = dto.HealthStatus{Status: "ok"}
		}
	} else {
		response.Components["keystore"] = dto.HealthStatus{
			Status:  "error",
			Message: "issuer not initialized",
		}
		hasCriticalErrors = true
	}

	// 3) Global DB (no crítico en FS-only)
	if s.deps.DBCheck != nil {
		if err := s.deps.DBCheck(ctx); err != nil {
			response.Components["db_global"] = dto.HealthStatus{
				Status:  "error",
				Message: fmt.Sprintf("unavailable: %v", err),
			}
			hasErrors = true
			log.Error("db_global unavailable", logger.Err(err))
		} else {
			response.Components["db_global"] = dto.HealthStatus{Status: "ok"}
		}
	} else {
		response.Components["db_global"] = dto.HealthStatus{
			Status:  "disabled",
			Message: "FS-only mode",
		}
	}

	// 4) Redis/Cache (no crítico)
	if s.deps.RedisCheck != nil {
		if err := s.deps.RedisCheck(ctx); err != nil {
			response.Components["redis"] = dto.HealthStatus{
				Status:  "error",
				Message: fmt.Sprintf("unavailable: %v", err),
			}
			hasErrors = true
			log.Error("redis unavailable", logger.Err(err))
		} else {
			response.Components["redis"] = dto.HealthStatus{Status: "ok"}
		}
	} else {
		response.Components["redis"] = dto.HealthStatus{
			Status:  "disabled",
			Message: "memory cache only",
		}
	}

	// 5) Tenant Pools (informativo)
	if s.deps.TenantPools != nil {
		stats := s.deps.TenantPools.Stats()
		var acquired, idle, total int
		for _, st := range stats {
			acquired += int(st.Acquired)
			idle += int(st.Idle)
			total += int(st.Total)
		}
		response.Components["tenant_pools"] = dto.HealthStatus{
			Status:  "ok",
			Message: fmt.Sprintf("active pools: %d (acquired=%d idle=%d total=%d)", len(stats), acquired, idle, total),
		}
	} else {
		response.Components["tenant_pools"] = dto.HealthStatus{Status: "disabled"}
	}

	// 6) Cluster info
	response.Cluster = s.buildClusterInfo()

	// 7) FS degraded flag
	if s.deps.FSDegraded != nil && s.deps.FSDegraded.Load() {
		response.FSDegraded = true
		hasErrors = true
	}

	// Status final
	if hasCriticalErrors {
		response.Status = "unavailable"
	} else if hasErrors {
		response.Status = "degraded"
	} else {
		response.Status = "ready"
	}

	return response
}

func (s *healthService) checkKeystore(ctx context.Context) error {
	now := time.Now().UTC()
	claims := jwtv5.MapClaims{
		"iss": s.deps.Issuer.Iss,
		"sub": "selfcheck",
		"aud": "health",
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(60 * time.Second).Unix(),
	}

	signed, _, err := s.deps.Issuer.SignRaw(claims)
	if err != nil {
		return fmt.Errorf("sign failed: %w", err)
	}

	parsed, err := jwtv5.Parse(signed, s.deps.Issuer.Keyfunc(),
		jwtv5.WithValidMethods([]string{"EdDSA"}),
		jwtv5.WithIssuer(s.deps.Issuer.Iss),
	)
	if err != nil || !parsed.Valid {
		return fmt.Errorf("verify failed: %w", err)
	}

	return nil
}

func (s *healthService) buildClusterInfo() map[string]any {
	mode := "off"
	if s.deps.ClusterChecker != nil {
		mode = "embedded"
	}

	clusterInfo := map[string]any{
		"mode": mode,
	}

	if mode != "embedded" || s.deps.ClusterChecker == nil {
		return clusterInfo
	}

	role := "follower"
	if s.deps.ClusterChecker.IsLeader() {
		role = "leader"
	}

	st := s.deps.ClusterChecker.Stats()
	raftBlock := map[string]any{}

	for _, key := range []string{"applied_index", "commit_index", "last_log_index", "last_snapshot_index", "num_peers", "state", "last_contact"} {
		if v, ok := st[key]; ok {
			raftBlock[key] = v
		}
	}

	clusterInfo["role"] = role
	clusterInfo["leader_id"] = s.deps.ClusterChecker.LeaderID()

	if v, ok := st["id"]; ok {
		clusterInfo["node_id"] = v
	}

	if len(s.deps.LeaderRedirects) > 0 {
		clusterInfo["leader_redirects"] = s.deps.LeaderRedirects
	}

	if n := s.deps.ClusterChecker.KnownPeers(); n > 0 {
		clusterInfo["peers_configured"] = n
	}

	if v, ok := st["num_peers"]; ok {
		clusterInfo["peers_connected"] = v
	}

	if len(raftBlock) > 0 {
		clusterInfo["raft"] = raftBlock
	}

	return clusterInfo
}
