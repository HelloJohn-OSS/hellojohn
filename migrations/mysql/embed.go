// Package mysql embeds SQL migration files for MySQL databases.
package mysql

import "embed"

// TenantFS contains the tenant migrations for per-tenant MySQL databases.
//
//go:embed tenant/*.sql
var TenantFS embed.FS

// TenantDir is the directory within TenantFS where migrations live.
const TenantDir = "tenant"

// GlobalDataPlaneFS contains the migrations for the shared MySQL Global Data Plane.
//
//go:embed global_data_plane/*.sql
var GlobalDataPlaneFS embed.FS

// GlobalDataPlaneDir is the directory within GlobalDataPlaneFS where migrations live.
const GlobalDataPlaneDir = "global_data_plane"
