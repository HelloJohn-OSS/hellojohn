package adaptive

import "time"

// Context contains runtime signals for adaptive MFA evaluation.
type Context struct {
	TenantID string
	UserID   string

	CurrentIP string
	CurrentUA string

	LastIP string
	LastUA string

	FailedAttempts int
	Now            time.Time
}
