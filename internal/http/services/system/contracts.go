// Package system implementa el servicio de administración del sistema.
package system

import (
	"context"

	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	metrics "github.com/dropDatabas3/hellojohn/internal/metrics"
)

// SystemService es la interfaz del servicio de sistema.
type SystemService interface {
	// GetStatus retorna el estado actual del sistema (modo, DB, contadores).
	GetStatus(ctx context.Context) (*dto.SystemStatusResult, error)
	// RunSync ejecuta (o simula con dry_run) la migración FS→DB.
	RunSync(ctx context.Context, req dto.SyncRequest) (*dto.SyncResult, error)
	// GetHealth agrega el estado del cluster, Global DB y uptime en un solo hit.
	GetHealth(ctx context.Context) (*dto.SystemHealthResult, error)
	// GetMetrics retorna un snapshot de las métricas en memoria del proceso.
	GetMetrics(ctx context.Context) (*dto.MetricsSummaryResult, error)
	// MetricsSnapshot retorna el snapshot actual de métricas.
	// ok=false si no hay collector configurado.
	MetricsSnapshot() (metrics.CollectorSnapshot, bool)
}
