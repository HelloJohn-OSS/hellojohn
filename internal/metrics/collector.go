package metrics

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const latencyRingSize = 2000

// Collector es un colector de métricas thread-safe en memoria.
// Los contadores se reinician al reiniciar el proceso.
type Collector struct {
	mu sync.RWMutex

	totalRequests int64
	totalErrors   int64

	latencies   [latencyRingSize]int64
	latencyIdx  int
	latencyFull bool

	routeMu      sync.RWMutex
	routeMetrics map[string]*RouteStats

	status2xx int64
	status3xx int64
	status4xx int64
	status5xx int64

	loginSuccess int64
	loginFailed  int64
	tokenIssued  int64
	tokenRevoked int64

	// Contadores adicionales SPRINT_07
	webhookDelivered int64
	webhookTotal     int64
	registrations    int64
	activations      int64
	passwordResets   int64

	// Hora de tráfico: ring buffer de 24 buckets (una por hora UTC)
	trafficMu     sync.RWMutex
	trafficByHour [24]int64 // índice = hora UTC (0-23)

	startTime time.Time
}

// RouteStats almacena contadores por ruta HTTP.
type RouteStats struct {
	Count  int64
	Errors int64
}

// NewCollector crea un nuevo Collector inicializado.
func NewCollector() *Collector {
	return &Collector{
		routeMetrics: make(map[string]*RouteStats, 64),
		startTime:    time.Now(),
	}
}

// Record registra la finalización de un request HTTP.
func (c *Collector) Record(route string, statusCode int, latency time.Duration) {
	atomic.AddInt64(&c.totalRequests, 1)

	switch {
	case statusCode >= 500:
		atomic.AddInt64(&c.status5xx, 1)
		atomic.AddInt64(&c.totalErrors, 1)
	case statusCode >= 400:
		atomic.AddInt64(&c.status4xx, 1)
		atomic.AddInt64(&c.totalErrors, 1)
	case statusCode >= 300:
		atomic.AddInt64(&c.status3xx, 1)
	default:
		atomic.AddInt64(&c.status2xx, 1)
	}

	c.mu.Lock()
	idx := c.latencyIdx
	c.latencies[idx] = latency.Nanoseconds()
	c.latencyIdx = (idx + 1) % latencyRingSize
	if !c.latencyFull && c.latencyIdx == 0 {
		c.latencyFull = true
	}
	c.mu.Unlock()

	c.routeMu.Lock()
	if len(c.routeMetrics) < 100 || c.routeMetrics[route] != nil {
		stats := c.routeMetrics[route]
		if stats == nil {
			stats = &RouteStats{}
			c.routeMetrics[route] = stats
		}
		atomic.AddInt64(&stats.Count, 1)
		if statusCode >= 400 {
			atomic.AddInt64(&stats.Errors, 1)
		}
	}
	c.routeMu.Unlock()
}

// RecordLogin registra un evento de login.
func (c *Collector) RecordLogin(success bool) {
	if success {
		atomic.AddInt64(&c.loginSuccess, 1)
	} else {
		atomic.AddInt64(&c.loginFailed, 1)
	}
}

// RecordToken registra emisión o revocación de token.
func (c *Collector) RecordToken(issued bool) {
	if issued {
		atomic.AddInt64(&c.tokenIssued, 1)
	} else {
		atomic.AddInt64(&c.tokenRevoked, 1)
	}
}

// RecordWebhook registra entrega de webhook.
func (c *Collector) RecordWebhook(delivered bool) {
	atomic.AddInt64(&c.webhookTotal, 1)
	if delivered {
		atomic.AddInt64(&c.webhookDelivered, 1)
	}
}

// RecordRegistration registra un nuevo usuario registrado.
func (c *Collector) RecordRegistration(activated bool) {
	atomic.AddInt64(&c.registrations, 1)
	if activated {
		atomic.AddInt64(&c.activations, 1)
	}
}

// RecordPasswordReset registra un reseteo de contraseña.
func (c *Collector) RecordPasswordReset() {
	atomic.AddInt64(&c.passwordResets, 1)
}

// RecordHourlyTraffic registra un request en el bucket de la hora actual.
func (c *Collector) RecordHourlyTraffic() {
	hour := time.Now().UTC().Hour()
	c.trafficMu.Lock()
	c.trafficByHour[hour]++
	c.trafficMu.Unlock()
}

// CollectorSnapshot es una copia inmutable de las métricas.
type CollectorSnapshot struct {
	TotalRequests int64
	TotalErrors   int64
	RequestRate   float64
	Status2xx     int64
	Status3xx     int64
	Status4xx     int64
	Status5xx     int64
	Routes        map[string]RouteStats
	Latencies     []int64 // nanoseconds
	LoginSuccess  int64
	LoginFailed   int64
	TokenIssued   int64
	TokenRevoked  int64
	UptimeSeconds float64

	// Campos adicionales SPRINT_07
	WebhookDelivered int64
	WebhookTotal     int64
	Registrations    int64
	Activations      int64
	PasswordResets   int64
	TrafficByHour    [24]int64
}

// Snapshot devuelve una copia inmutable de las métricas actuales.
func (c *Collector) Snapshot() CollectorSnapshot {
	uptime := time.Since(c.startTime)

	c.mu.RLock()
	latsCopy := make([]int64, 0, latencyRingSize)
	if c.latencyFull {
		latsCopy = append(latsCopy, c.latencies[:]...)
	} else {
		latsCopy = append(latsCopy, c.latencies[:c.latencyIdx]...)
	}
	c.mu.RUnlock()

	c.routeMu.RLock()
	routes := make(map[string]RouteStats, len(c.routeMetrics))
	for k, v := range c.routeMetrics {
		routes[k] = RouteStats{
			Count:  atomic.LoadInt64(&v.Count),
			Errors: atomic.LoadInt64(&v.Errors),
		}
	}
	c.routeMu.RUnlock()

	total := atomic.LoadInt64(&c.totalRequests)
	var reqRate float64
	if uptime.Seconds() > 0 {
		reqRate = float64(total) / uptime.Seconds()
	}

	c.trafficMu.RLock()
	var hourCopy [24]int64
	for i, v := range c.trafficByHour {
		hourCopy[i] = v
	}
	c.trafficMu.RUnlock()

	return CollectorSnapshot{
		TotalRequests:    total,
		TotalErrors:      atomic.LoadInt64(&c.totalErrors),
		RequestRate:      reqRate,
		Status2xx:        atomic.LoadInt64(&c.status2xx),
		Status3xx:        atomic.LoadInt64(&c.status3xx),
		Status4xx:        atomic.LoadInt64(&c.status4xx),
		Status5xx:        atomic.LoadInt64(&c.status5xx),
		Routes:           routes,
		Latencies:        latsCopy,
		LoginSuccess:     atomic.LoadInt64(&c.loginSuccess),
		LoginFailed:      atomic.LoadInt64(&c.loginFailed),
		TokenIssued:      atomic.LoadInt64(&c.tokenIssued),
		TokenRevoked:     atomic.LoadInt64(&c.tokenRevoked),
		UptimeSeconds:    uptime.Seconds(),
		WebhookDelivered: atomic.LoadInt64(&c.webhookDelivered),
		WebhookTotal:     atomic.LoadInt64(&c.webhookTotal),
		Registrations:    atomic.LoadInt64(&c.registrations),
		Activations:      atomic.LoadInt64(&c.activations),
		PasswordResets:   atomic.LoadInt64(&c.passwordResets),
		TrafficByHour:    hourCopy,
	}
}

// WebhookDeliveryRate retorna el porcentaje de webhooks entregados.
func (s CollectorSnapshot) WebhookDeliveryRate() float64 {
	if s.WebhookTotal == 0 {
		return 100.0
	}
	return float64(s.WebhookDelivered) / float64(s.WebhookTotal) * 100
}

// LoginSuccessRate retorna el porcentaje de logins exitosos.
func (s CollectorSnapshot) LoginSuccessRate() float64 {
	total := s.LoginSuccess + s.LoginFailed
	if total == 0 {
		return 100.0
	}
	return float64(s.LoginSuccess) / float64(total) * 100
}

// ConversionRate retorna la tasa de activación sobre registros.
func (s CollectorSnapshot) ConversionRate() float64 {
	if s.Registrations == 0 {
		return 0
	}
	return float64(s.Activations) / float64(s.Registrations) * 100
}

// PercentilesMs calcula P50 y P99 en milisegundos.
func (s CollectorSnapshot) PercentilesMs() (p50, p99 float64) {
	if len(s.Latencies) == 0 {
		return 0, 0
	}
	sorted := make([]int64, len(s.Latencies))
	copy(sorted, s.Latencies)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	p50 = float64(sorted[len(sorted)*50/100]) / 1e6
	p99 = float64(sorted[len(sorted)*99/100]) / 1e6
	return p50, p99
}
