package system

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"time"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	metrics "github.com/dropDatabas3/hellojohn/internal/metrics"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// SystemDeps contiene las dependencias del SystemService.
// NO usa os.Getenv — recibe todo via Deps inyectadas en wiring.go.
type SystemDeps struct {
	DAL          store.DataAccessLayer
	FSRoot       string
	GlobalDSN    string // para maskDSN en status — NUNCA se expone completo
	GlobalDriver string
	Logger       *log.Logger
	StartTime    time.Time          // startup time del proceso (para calcular uptime)
	Version      string             // build tag, vacío en dev
	Metrics      *metrics.Collector // nil si no está configurado
}

type systemService struct {
	deps SystemDeps
}

// New crea un nuevo SystemService.
func New(deps SystemDeps) SystemService {
	return &systemService{deps: deps}
}

// GetStatus retorna el estado actual del sistema.
func (s *systemService) GetStatus(ctx context.Context) (*dto.SystemStatusResult, error) {
	dal := s.deps.DAL
	mode := dal.Mode()

	result := &dto.SystemStatusResult{
		Mode:   mode.String(),
		FSRoot: s.deps.FSRoot,
	}

	// Contar tenants en FS
	inFS := s.countFSTenants()
	result.TenantCount.InFS = inFS

	// Estado de Global DB (solo si DSN está configurado)
	if s.deps.GlobalDSN != "" {
		dbInfo := &dto.DBStatusInfo{
			Driver:    s.deps.GlobalDriver,
			DSNMasked: maskDSN(s.deps.GlobalDSN),
		}

		// Intentar contar tenants en DB como proxy de conectividad
		tenants, err := dal.ConfigAccess().Tenants().List(ctx)
		if err != nil {
			dbInfo.Connected = false
			dbInfo.TenantCount = 0
		} else {
			dbInfo.Connected = true
			dbInfo.TenantCount = len(tenants)
		}

		result.GlobalDB = dbInfo
		result.TenantCount.InDB = dbInfo.TenantCount
	}

	return result, nil
}

// RunSync ejecuta o simula la migración FS→DB.
func (s *systemService) RunSync(ctx context.Context, req dto.SyncRequest) (*dto.SyncResult, error) {
	if s.deps.GlobalDSN == "" {
		return nil, fmt.Errorf("no global DB configured: set GLOBAL_CONTROL_PLANE_DSN to enable sync")
	}

	l := s.deps.Logger
	if l == nil {
		l = log.Default()
	}

	syncResult, err := store.RunSyncFS2DB(ctx, store.SyncConfig{
		FSRoot:       s.deps.FSRoot,
		GlobalDSN:    s.deps.GlobalDSN,
		GlobalDriver: s.deps.GlobalDriver,
		DryRun:       req.DryRun,
		Logger:       l,
	})
	if err != nil {
		return nil, fmt.Errorf("sync failed: %w", err)
	}

	return &dto.SyncResult{
		DryRun:           req.DryRun,
		TenantsProcessed: syncResult.TenantsProcessed,
		TenantsSkipped:   syncResult.TenantsSkipped,
		ClientsUpserted:  syncResult.ClientsUpserted,
		ScopesUpserted:   syncResult.ScopesUpserted,
		ClaimsUpserted:   syncResult.ClaimsUpserted,
		AdminsUpserted:   syncResult.AdminsUpserted,
		Errors:           syncResult.Errors,
	}, nil
}

// GetHealth agrega el estado del cluster, Global DB y uptime en un solo hit.
func (s *systemService) GetHealth(ctx context.Context) (*dto.SystemHealthResult, error) {
	result := &dto.SystemHealthResult{
		Status:  "healthy",
		Readyz:  true,
		Version: s.deps.Version,
		Uptime:  formatUptime(time.Since(s.deps.StartTime)),
	}

	// Database info
	if s.deps.GlobalDSN != "" {
		result.Database = dto.DatabaseHealthInfo{
			Configured: true,
			Driver:     s.deps.GlobalDriver,
			HostMasked: extractHost(s.deps.GlobalDSN),
		}
		// Intentar listar tenants como ping a la DB
		_, err := s.deps.DAL.ConfigAccess().Tenants().List(ctx)
		result.Database.Connected = (err == nil)
		if !result.Database.Connected {
			result.Status = "degraded"
		}
	}

	// Cluster info — modo standalone por defecto
	result.Cluster = dto.ClusterHealthInfo{
		Enabled:      false,
		TotalNodes:   1,
		HealthyNodes: 1,
		LeaderNode:   "local",
	}

	return result, nil
}

// MetricsSnapshot retorna el snapshot actual de métricas.
// ok=false si no hay collector configurado.
func (s *systemService) MetricsSnapshot() (metrics.CollectorSnapshot, bool) {
	if s.deps.Metrics == nil {
		return metrics.CollectorSnapshot{}, false
	}
	return s.deps.Metrics.Snapshot(), true
}

// GetMetrics retorna un snapshot de las métricas en memoria del proceso.
func (s *systemService) GetMetrics(ctx context.Context) (*dto.MetricsSummaryResult, error) {
	if s.deps.Metrics == nil {
		return &dto.MetricsSummaryResult{}, nil
	}
	snap := s.deps.Metrics.Snapshot()
	p50, p99 := snap.PercentilesMs()

	var errorRate float64
	if snap.TotalRequests > 0 {
		errorRate = float64(snap.TotalErrors) / float64(snap.TotalRequests)
	}

	topRoutes := buildTopRoutes(snap.Routes, snap.TotalRequests)

	return &dto.MetricsSummaryResult{
		UptimeSeconds: snap.UptimeSeconds,
		TotalRequests: snap.TotalRequests,
		RequestRate:   snap.RequestRate,
		ErrorRate:     errorRate,
		LatencyP50Ms:  p50,
		LatencyP99Ms:  p99,
		StatusCodes: dto.MetricsStatusCodes{
			S2xx: snap.Status2xx,
			S3xx: snap.Status3xx,
			S4xx: snap.Status4xx,
			S5xx: snap.Status5xx,
		},
		TopRoutes: topRoutes,
		AuthEvents: dto.MetricsAuthEvents{
			LoginSuccess: snap.LoginSuccess,
			LoginFailed:  snap.LoginFailed,
			TokenIssued:  snap.TokenIssued,
			TokenRevoked: snap.TokenRevoked,
		},
	}, nil
}

// buildTopRoutes construye el top 10 de rutas por conteo.
func buildTopRoutes(routes map[string]metrics.RouteStats, total int64) []dto.RouteMetricItem {
	items := make([]dto.RouteMetricItem, 0, len(routes))
	for route, stats := range routes {
		var errRate float64
		if stats.Count > 0 {
			errRate = float64(stats.Errors) / float64(stats.Count)
		}
		var pct float64
		if total > 0 {
			pct = float64(stats.Count) / float64(total) * 100
		}
		items = append(items, dto.RouteMetricItem{
			Route:     route,
			Count:     stats.Count,
			ErrorRate: errRate,
			Percent:   pct,
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Count > items[j].Count })
	if len(items) > 10 {
		items = items[:10]
	}
	return items
}

// formatUptime convierte duration a "Xd Xh Xm"
func formatUptime(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

// extractHost extrae solo host:port del DSN, sin credenciales.
func extractHost(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return "***"
	}
	return u.Host
}

// countFSTenants cuenta los directorios dentro de <FSRoot>/tenants/.
func (s *systemService) countFSTenants() int {
	tenantsDir := filepath.Join(s.deps.FSRoot, "tenants")
	entries, err := os.ReadDir(tenantsDir)
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() {
			count++
		}
	}
	return count
}

// maskDSN extrae solo scheme://***@host:port/db del DSN, ocultando credenciales.
// Ejemplo: "postgres://admin:secret@prod-db:5432/hellojohn_cp?sslmode=require"
// → "postgres://***@prod-db:5432/hellojohn_cp"
//
// INVARIANTE: esta función NUNCA debe retornar user o password.
func maskDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return "***"
	}
	// Reemplazar credenciales con ***
	u.User = url.User("***")
	// No exponer query params (pueden contener passwords)
	u.RawQuery = ""
	return u.String()
}
