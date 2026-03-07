package admin

// MetricsSummaryResult — respuesta de GET /v2/admin/system/metrics/summary
type MetricsSummaryResult struct {
	UptimeSeconds float64            `json:"uptime_seconds"`
	TotalRequests int64              `json:"total_requests"`
	RequestRate   float64            `json:"request_rate"`
	ErrorRate     float64            `json:"error_rate"`
	LatencyP50Ms  float64            `json:"latency_p50_ms"`
	LatencyP99Ms  float64            `json:"latency_p99_ms"`
	StatusCodes   MetricsStatusCodes `json:"status_codes"`
	TopRoutes     []RouteMetricItem  `json:"top_routes"`
	AuthEvents    MetricsAuthEvents  `json:"auth_events"`
}

// MetricsStatusCodes agrupa requests por clase de status HTTP.
type MetricsStatusCodes struct {
	S2xx int64 `json:"2xx"`
	S3xx int64 `json:"3xx"`
	S4xx int64 `json:"4xx"`
	S5xx int64 `json:"5xx"`
}

// RouteMetricItem representa métricas de una ruta específica.
type RouteMetricItem struct {
	Route     string  `json:"route"`
	Count     int64   `json:"count"`
	ErrorRate float64 `json:"error_rate"`
	Percent   float64 `json:"percent"`
}

// MetricsAuthEvents contiene contadores de eventos de autenticación.
type MetricsAuthEvents struct {
	LoginSuccess int64 `json:"login_success"`
	LoginFailed  int64 `json:"login_failed"`
	TokenIssued  int64 `json:"token_issued"`
	TokenRevoked int64 `json:"token_revoked"`
}
