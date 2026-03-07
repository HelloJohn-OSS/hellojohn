// Package system agrupa los controllers del dominio de administración del sistema.
package system

import (
	"net/http"

	syssvc "github.com/dropDatabas3/hellojohn/internal/http/services/system"
	metrics "github.com/dropDatabas3/hellojohn/internal/metrics"
)

// Controllers agrupa todos los controllers del dominio system.
type Controllers struct {
	Status          *StatusController
	MetricsDetailed http.Handler
}

// NewControllers crea un nuevo conjunto de controllers del dominio system.
// El collector es opcional — si se omite, GET /metrics/detailed retorna 404.
func NewControllers(svc syssvc.SystemService, collector ...*metrics.Collector) *Controllers {
	var collectorVal *metrics.Collector
	if len(collector) > 0 {
		collectorVal = collector[0]
	}
	return &Controllers{
		Status: NewStatusController(svc),
		MetricsDetailed: NewMetricsDetailedHandler(MetricsDetailedDeps{
			Collector: collectorVal,
		}),
	}
}
