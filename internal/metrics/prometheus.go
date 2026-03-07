package metrics

import (
	"fmt"
	"io"
)

// WritePrometheusFormat escribe las métricas en formato Prometheus text exposition 0.0.4.
// Content-Type debe ser: text/plain; version=0.0.4; charset=utf-8
func WritePrometheusFormat(w io.Writer, snap CollectorSnapshot) {
	p50, p99 := snap.PercentilesMs()

	// ─── HTTP Requests Total ───
	fmt.Fprintf(w, "# HELP hellojohn_http_requests_total Total number of HTTP requests since startup\n")
	fmt.Fprintf(w, "# TYPE hellojohn_http_requests_total counter\n")
	fmt.Fprintf(w, "hellojohn_http_requests_total %d\n\n", snap.TotalRequests)

	// ─── HTTP Errors Total ───
	fmt.Fprintf(w, "# HELP hellojohn_http_errors_total Total number of HTTP errors (4xx + 5xx) since startup\n")
	fmt.Fprintf(w, "# TYPE hellojohn_http_errors_total counter\n")
	fmt.Fprintf(w, "hellojohn_http_errors_total %d\n\n", snap.TotalErrors)

	// ─── Latency Percentiles ───
	fmt.Fprintf(w, "# HELP hellojohn_http_request_duration_p50_ms P50 request latency in milliseconds\n")
	fmt.Fprintf(w, "# TYPE hellojohn_http_request_duration_p50_ms gauge\n")
	fmt.Fprintf(w, "hellojohn_http_request_duration_p50_ms %.3f\n\n", p50)

	fmt.Fprintf(w, "# HELP hellojohn_http_request_duration_p99_ms P99 request latency in milliseconds\n")
	fmt.Fprintf(w, "# TYPE hellojohn_http_request_duration_p99_ms gauge\n")
	fmt.Fprintf(w, "hellojohn_http_request_duration_p99_ms %.3f\n\n", p99)

	// ─── Status Codes ───
	fmt.Fprintf(w, "# HELP hellojohn_http_requests_by_status HTTP requests grouped by status class\n")
	fmt.Fprintf(w, "# TYPE hellojohn_http_requests_by_status counter\n")
	fmt.Fprintf(w, "hellojohn_http_requests_by_status{status=\"2xx\"} %d\n", snap.Status2xx)
	fmt.Fprintf(w, "hellojohn_http_requests_by_status{status=\"3xx\"} %d\n", snap.Status3xx)
	fmt.Fprintf(w, "hellojohn_http_requests_by_status{status=\"4xx\"} %d\n", snap.Status4xx)
	fmt.Fprintf(w, "hellojohn_http_requests_by_status{status=\"5xx\"} %d\n\n", snap.Status5xx)

	// ─── Auth Events ───
	fmt.Fprintf(w, "# HELP hellojohn_auth_logins_total Login attempts by result\n")
	fmt.Fprintf(w, "# TYPE hellojohn_auth_logins_total counter\n")
	fmt.Fprintf(w, "hellojohn_auth_logins_total{result=\"success\"} %d\n", snap.LoginSuccess)
	fmt.Fprintf(w, "hellojohn_auth_logins_total{result=\"failed\"} %d\n\n", snap.LoginFailed)

	fmt.Fprintf(w, "# HELP hellojohn_auth_tokens_total Token operations by type\n")
	fmt.Fprintf(w, "# TYPE hellojohn_auth_tokens_total counter\n")
	fmt.Fprintf(w, "hellojohn_auth_tokens_total{op=\"issued\"} %d\n", snap.TokenIssued)
	fmt.Fprintf(w, "hellojohn_auth_tokens_total{op=\"revoked\"} %d\n\n", snap.TokenRevoked)

	// ─── Uptime ───
	fmt.Fprintf(w, "# HELP hellojohn_process_uptime_seconds Seconds since process start\n")
	fmt.Fprintf(w, "# TYPE hellojohn_process_uptime_seconds gauge\n")
	fmt.Fprintf(w, "hellojohn_process_uptime_seconds %.1f\n", snap.UptimeSeconds)
}
