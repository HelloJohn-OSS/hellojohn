// Package health contiene DTOs para endpoints de health check.
package health

import "time"

// HealthStatus representa el estado de un componente específico.
type HealthStatus struct {
	Status  string `json:"status"`            // "ok" | "error" | "disabled"
	Message string `json:"message,omitempty"` // Detalle opcional
}

// HealthResponse representa la respuesta de salud completa.
type HealthResponse struct {
	Status      string                  `json:"status"` // "ready" | "degraded" | "unavailable"
	Components  map[string]HealthStatus `json:"components"`
	Version     string                  `json:"version,omitempty"`
	Commit      string                  `json:"commit,omitempty"`
	ActiveKeyID string                  `json:"active_key_id,omitempty"`
	Timestamp   time.Time               `json:"timestamp"`
	Cluster     map[string]any          `json:"cluster,omitempty"`
	FSDegraded  bool                    `json:"fs_degraded,omitempty"`
}
