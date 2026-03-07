package metrics

import (
	"testing"
	"time"
)

// BenchmarkMAUTracking mide el throughput del collector de métricas in-memory
// bajo carga concurrente (equivalente a tracking de MAU con múltiples goroutines).
//
// Criterio de aceptación MVP: > 10,000 ops/segundo.
func BenchmarkMAUTracking(b *testing.B) {
	c := NewCollector()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.RecordLogin(true)
			c.RecordHourlyTraffic()
		}
	})
}

// BenchmarkCollectorSnapshot mide el costo de leer un snapshot completo del collector.
// Útil para medir la overhead de los endpoints de métricas bajo carga.
func BenchmarkCollectorSnapshot(b *testing.B) {
	c := NewCollector()

	// Poblar con datos reales antes de medir
	for i := 0; i < 1000; i++ {
		c.Record("/v2/auth/login", 200, time.Millisecond*5)
		c.RecordLogin(true)
		c.RecordToken(true)
		c.RecordRegistration(true)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.Snapshot()
	}
}

// BenchmarkRecordConcurrent mide el throughput de Record() con múltiples
// goroutines y rutas distintas (simula tráfico real del servidor).
func BenchmarkRecordConcurrent(b *testing.B) {
	c := NewCollector()
	routes := []string{
		"/v2/auth/login",
		"/v2/auth/register",
		"/v2/auth/refresh",
		"/oauth2/token",
		"/.well-known/openid-configuration",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			route := routes[i%len(routes)]
			c.Record(route, 200, time.Millisecond)
			i++
		}
	})
}
