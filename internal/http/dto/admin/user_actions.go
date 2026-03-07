package admin

import "time"

// DisableUserRequest is the request for POST /v2/admin/users/disable.
type DisableUserRequest struct {
	UserID   string `json:"user_id"`
	TenantID string `json:"tenant_id,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Duration string `json:"duration,omitempty"` // e.g. "24h", "2h30m"
}

// EnableUserRequest is the request for POST /v2/admin/users/enable.
type EnableUserRequest struct {
	UserID   string `json:"user_id"`
	TenantID string `json:"tenant_id,omitempty"`
}

// ResendVerificationRequest is the request for POST /v2/admin/users/resend-verification.
type ResendVerificationRequest struct {
	UserID   string `json:"user_id"`
	TenantID string `json:"tenant_id"`
}

// UserActionResult contains the result of a user action.
type UserActionResult struct {
	UserID   string     `json:"user_id"`
	Action   string     `json:"action"`
	Until    *time.Time `json:"until,omitempty"`
	Notified bool       `json:"notified,omitempty"`
}
