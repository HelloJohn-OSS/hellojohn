package admin

import "time"

// CreateUserRequest para POST /v2/admin/tenants/{id}/users
type CreateUserRequest struct {
	Email          string         `json:"email"`
	Password       string         `json:"password"` // Texto plano, el servidor lo hashea
	Name           string         `json:"name,omitempty"`
	GivenName      string         `json:"given_name,omitempty"`
	FamilyName     string         `json:"family_name,omitempty"`
	Picture        string         `json:"picture,omitempty"`
	Locale         string         `json:"locale,omitempty"`
	EmailVerified  bool           `json:"email_verified,omitempty"`
	SourceClientID string         `json:"source_client_id,omitempty"`
	CustomFields   map[string]any `json:"custom_fields,omitempty"`
}

// UpdateUserRequest para PUT /v2/admin/tenants/{id}/users/{userId}
type UpdateUserRequest struct {
	Name           *string         `json:"name,omitempty"`
	GivenName      *string         `json:"given_name,omitempty"`
	FamilyName     *string         `json:"family_name,omitempty"`
	Picture        *string         `json:"picture,omitempty"`
	Locale         *string         `json:"locale,omitempty"`
	SourceClientID *string         `json:"source_client_id,omitempty"`
	CustomFields   *map[string]any `json:"custom_fields,omitempty"`
}

// UserResponse para GET responses
type UserResponse struct {
	ID             string         `json:"id"`
	TenantID       string         `json:"tenant_id"`
	Email          string         `json:"email"`
	Name           string         `json:"name,omitempty"`
	GivenName      string         `json:"given_name,omitempty"`
	FamilyName     string         `json:"family_name,omitempty"`
	Picture        string         `json:"picture,omitempty"`
	Locale         string         `json:"locale,omitempty"`
	EmailVerified  bool           `json:"email_verified"`
	SourceClientID *string        `json:"source_client_id,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
	DisabledAt     *time.Time     `json:"disabled_at,omitempty"`
	DisabledUntil  *time.Time     `json:"disabled_until,omitempty"`
	DisabledReason *string        `json:"disabled_reason,omitempty"`
	DisabledBy     *string        `json:"disabled_by,omitempty"`
	CustomFields   map[string]any `json:"custom_fields,omitempty"`
}

// ListUsersResponse para GET /v2/admin/tenants/{id}/users
type ListUsersResponse struct {
	Users      []UserResponse `json:"users"`
	TotalCount int            `json:"total_count"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
}
