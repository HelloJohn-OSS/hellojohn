package repository

import (
	"context"
	"time"
)

// TenantUsageStats represents aggregated usage counters for one tenant/month.
type TenantUsageStats struct {
	TenantID           string    `json:"tenant_id"`
	Month              time.Time `json:"month"`
	MAU                int       `json:"mau"`
	TotalLogins        int       `json:"total_logins"`
	TotalRegistrations int       `json:"total_registrations"`
	TotalTokensIssued  int       `json:"total_tokens_issued"`
	TotalAPICalls      int       `json:"total_api_calls"`
}

// UsageRepository stores and queries usage analytics.
type UsageRepository interface {
	IncrementMAU(ctx context.Context, tenantID, userID string, month time.Time) error
	IncrementCounter(ctx context.Context, tenantID string, month time.Time, field string, delta int) error
	GetUsage(ctx context.Context, tenantID string, month time.Time) (*TenantUsageStats, error)
	GetUsageHistory(ctx context.Context, tenantID string, months int) ([]TenantUsageStats, error)
	ListTopTenants(ctx context.Context, month time.Time, limit int) ([]TenantUsageStats, error)
}
