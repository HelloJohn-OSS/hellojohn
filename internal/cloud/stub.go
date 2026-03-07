package cloud

import "context"

// HealthChecker is a no-op in OSS builds.
type HealthChecker struct{}

func NewHealthChecker(_ any) *HealthChecker { return &HealthChecker{} }

func (h *HealthChecker) Start(_ context.Context) {}
