package admin

import (
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

// ─── Request DTOs ───

// CreateAdminRequest crea un nuevo admin (directo o por invite).
type CreateAdminRequest struct {
	Email        string                         `json:"email"`
	Name         string                         `json:"name,omitempty"`
	Type         string                         `json:"type"`                        // "global" | "tenant"
	TenantAccess []repository.TenantAccessEntry `json:"tenant_access,omitempty"`     // Solo para type=tenant
	TenantRole   string                         `json:"tenant_role,omitempty"`       // rol por defecto: "member"
	Password     string                         `json:"password,omitempty"`          // Requerido si SendInvite=false
	SendInvite   bool                           `json:"send_invite"`                 // true = enviar email invite
}

// UpdateAdminRequest actualiza campos del admin.
type UpdateAdminRequest struct {
	Email        *string                        `json:"email,omitempty"`
	Name         *string                        `json:"name,omitempty"`
	TenantAccess []repository.TenantAccessEntry `json:"tenant_access,omitempty"`
}

// AcceptInviteRequest acepta un invite y establece la contraseña.
type AcceptInviteRequest struct {
	Token    string `json:"token"`    // Token raw del email
	Password string `json:"password"` // Contraseña a establecer
}

// ─── Response DTOs ───

// AdminResponse representa un admin en respuestas de API.
type AdminResponse struct {
	ID           string                       `json:"id"`
	Email        string                       `json:"email"`
	Name         string                       `json:"name,omitempty"`
	Type         string                       `json:"type"` // "global" | "tenant"
	TenantAccess []repository.TenantAccessEntry `json:"tenant_access,omitempty"`
	Status       string                       `json:"status"` // "active" | "pending" | "disabled"
	LastSeenAt      *time.Time `json:"last_seen_at,omitempty"`
	DisabledAt      *time.Time `json:"disabled_at,omitempty"`
	InviteExpiresAt *time.Time `json:"invite_expires_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// ValidateInviteResponse es la respuesta al validar un token de invite.
type ValidateInviteResponse struct {
	Valid     bool   `json:"valid"`
	AdminID   string `json:"admin_id"`
	Email     string `json:"email"`
	Name      string `json:"name,omitempty"`
	ExpiresAt string `json:"expires_at"`
}

// AdminListResponse es la respuesta de listado de admins.
type AdminListResponse struct {
	Admins []AdminResponse `json:"admins"`
	Total  int             `json:"total"`
}
