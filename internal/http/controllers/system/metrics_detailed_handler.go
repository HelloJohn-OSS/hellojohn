package system

import (
	"encoding/json"
	"net/http"
	"time"

	metrics "github.com/dropDatabas3/hellojohn/internal/metrics"
)

// MetricsDetailedDeps son las dependencias para el handler de métricas detalladas.
type MetricsDetailedDeps struct {
	Collector *metrics.Collector
}

// metricsDetailedHandler maneja GET /v2/admin/system/metrics/detailed.
type metricsDetailedHandler struct {
	deps MetricsDetailedDeps
}

// NewMetricsDetailedHandler crea un handler para métricas detalladas.
func NewMetricsDetailedHandler(deps MetricsDetailedDeps) http.Handler {
	return &metricsDetailedHandler{deps: deps}
}

func (h *metricsDetailedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.deps.Collector == nil {
		http.NotFound(w, r)
		return
	}

	rangeStr := r.URL.Query().Get("range")
	if rangeStr == "" {
		rangeStr = "24h"
	}

	snap := h.deps.Collector.Snapshot()
	p50, p99 := snap.PercentilesMs()

	type TopTenant struct {
		Slug string `json:"slug"`
		MAU  int    `json:"mau"`
	}

	type Response struct {
		Range       string `json:"range"`
		GeneratedAt string `json:"generated_at"`
		Summary     struct {
			TotalUsers          int     `json:"total_users"`
			DAU                 int     `json:"dau"`
			MAU                 int     `json:"mau"`
			LoginSuccessRate    float64 `json:"login_success_rate"`
			MFAAdoption         float64 `json:"mfa_adoption"`
			WebhookDeliveryRate float64 `json:"webhook_delivery_rate"`
			SystemUptimeHours   float64 `json:"system_uptime_hours"`
			TotalErrors         int64   `json:"total_errors"`
			Status4xx           int64   `json:"status_4xx"`
			Status5xx           int64   `json:"status_5xx"`
			LatencyP50ms        float64 `json:"latency_p50_ms"`
			LatencyP99ms        float64 `json:"latency_p99_ms"`
			TotalRequests       int64   `json:"total_requests"`
			LoginTotal          int64   `json:"login_total"`
			TokenIssued         int64   `json:"token_issued"`
			Registrations       int64   `json:"registrations"`
			PasswordResets      int64   `json:"password_resets"`
		} `json:"summary"`
		TrafficByHour [24]int64   `json:"traffic_by_hour"`
		TopTenants    []TopTenant `json:"top_tenants"`
	}

	var resp Response
	resp.Range = rangeStr
	resp.GeneratedAt = time.Now().UTC().Format(time.RFC3339)

	resp.Summary.LoginSuccessRate = snap.LoginSuccessRate()
	resp.Summary.WebhookDeliveryRate = snap.WebhookDeliveryRate()
	resp.Summary.SystemUptimeHours = snap.UptimeSeconds / 3600
	resp.Summary.TotalErrors = snap.TotalErrors
	resp.Summary.Status4xx = snap.Status4xx
	resp.Summary.Status5xx = snap.Status5xx
	resp.Summary.LatencyP50ms = p50
	resp.Summary.LatencyP99ms = p99
	resp.Summary.TotalRequests = snap.TotalRequests
	resp.Summary.LoginTotal = snap.LoginSuccess + snap.LoginFailed
	resp.Summary.TokenIssued = snap.TokenIssued
	resp.Summary.Registrations = snap.Registrations
	resp.Summary.PasswordResets = snap.PasswordResets
	resp.TrafficByHour = snap.TrafficByHour
	resp.TopTenants = []TopTenant{} // TODO: llenar desde repos cuando SPRINT_02 esté completo

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}
