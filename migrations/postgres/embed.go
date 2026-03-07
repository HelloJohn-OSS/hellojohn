// Package migrations embeds SQL migration files.
package migrations

import "embed"

// TenantFS contains the tenant migrations for per-tenant databases.
//
//go:embed tenant
var TenantFS embed.FS

// TenantDir is the directory within TenantFS where migrations live.
const TenantDir = "tenant"

// GlobalFS contains the global control plane migrations (cp_tenant, cp_client, etc.).
//
//go:embed global/*.sql
var GlobalFS embed.FS

// GlobalDir is the directory within GlobalFS where global migrations live.
const GlobalDir = "global"

// GlobalDataPlaneFS contains the Global Data Plane migrations (shared tenant data with RLS).
//
//go:embed global_data_plane/*.sql
var GlobalDataPlaneFS embed.FS

// GlobalDataPlaneDir is the directory within GlobalDataPlaneFS where GDP migrations live.
const GlobalDataPlaneDir = "global_data_plane"
