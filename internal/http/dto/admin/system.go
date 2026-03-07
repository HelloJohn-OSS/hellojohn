package admin

// SystemStatusResult es el resultado del endpoint GET /v2/system/status.
type SystemStatusResult struct {
	Mode        string            `json:"mode"`                // "fs_only" | "fs_global_db" | "fs_tenant_db" | "full_db"
	GlobalDB    *DBStatusInfo     `json:"global_db,omitempty"` // nil si no hay Global DB configurada
	FSRoot      string            `json:"fs_root"`
	TenantCount SystemTenantCount `json:"tenant_count"`
	Version     string            `json:"version,omitempty"`
	Uptime      string            `json:"uptime,omitempty"`
}

// DBStatusInfo contiene el estado de la Global DB.
type DBStatusInfo struct {
	Connected   bool   `json:"connected"`
	Driver      string `json:"driver"`       // "pg" | "mysql"
	DSNMasked   string `json:"dsn_masked"`   // "postgres://***@host:5432/db" — nunca credenciales
	TenantCount int    `json:"tenant_count"` // filas en cp_tenant
}

// SystemTenantCount muestra la cantidad de tenants en FS y en DB.
type SystemTenantCount struct {
	InFS int `json:"in_fs"` // directorios en FS_ROOT/tenants/
	InDB int `json:"in_db"` // filas en cp_tenant (0 si no hay DB)
}

// SyncRequest es el body de POST /v2/system/sync.
type SyncRequest struct {
	DryRun bool `json:"dry_run"`
}

// SyncResult es la respuesta de POST /v2/system/sync.
type SyncResult struct {
	DryRun           bool     `json:"dry_run"`
	TenantsProcessed int      `json:"tenants_processed"`
	TenantsSkipped   int      `json:"tenants_skipped"`
	ClientsUpserted  int      `json:"clients_upserted"`
	ScopesUpserted   int      `json:"scopes_upserted"`
	ClaimsUpserted   int      `json:"claims_upserted"`
	AdminsUpserted   int      `json:"admins_upserted"`
	Errors           []string `json:"errors"`
}

// ─── System Health ───────────────────────────────────────────────────────────

// SystemHealthResult — respuesta de GET /v2/system/health
type SystemHealthResult struct {
	Status   string             `json:"status"`   // "healthy" | "degraded" | "unhealthy"
	Uptime   string             `json:"uptime"`
	Version  string             `json:"version"`
	Cluster  ClusterHealthInfo  `json:"cluster"`
	Database DatabaseHealthInfo `json:"database"`
	Readyz   bool               `json:"readyz"`
}

type ClusterHealthInfo struct {
	Enabled      bool   `json:"enabled"`
	TotalNodes   int    `json:"total_nodes"`
	HealthyNodes int    `json:"healthy_nodes"`
	LeaderNode   string `json:"leader_node"`
}

type DatabaseHealthInfo struct {
	Configured bool   `json:"configured"`
	Connected  bool   `json:"connected"`
	Driver     string `json:"driver"`
	HostMasked string `json:"host_masked"`
}
