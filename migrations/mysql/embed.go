// Package mysql embeds SQL migration files for MySQL databases.
package mysql

import "embed"

// TenantFS contains the tenant migrations for per-tenant MySQL databases.
//
//go:embed tenant/*.sql
var TenantFS embed.FS

// TenantDir is the directory within TenantFS where migrations live.
const TenantDir = "tenant"
