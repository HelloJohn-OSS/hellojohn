package audit

import (
	cryptoRand "crypto/rand"
	"fmt"
	"sync/atomic"
	"time"
)

// fallbackSeq is a monotonic counter used by generateID when crypto/rand
// is unavailable, ensuring uniqueness across concurrent callers.
var fallbackSeq atomic.Uint64

// EventType identifies the kind of audit event.
type EventType string

// ─── User Authentication Events ───

const (
	EventLogin          EventType = "user.login"
	EventLoginFailed    EventType = "user.login_failed"
	EventRegister       EventType = "user.register"
	EventLogout         EventType = "user.logout"
	EventPasswordChange EventType = "user.password_change"
	EventPasswordReset  EventType = "user.password_reset"
	EventSocialLogin    EventType = "user.social_login"
	EventMagicLink      EventType = "user.magic_link"
	EventOTPLogin       EventType = "user.otp_login"
)

// ─── MFA Events ───

const (
	EventMFAEnroll  EventType = "user.mfa_enroll"
	EventMFAVerify  EventType = "user.mfa_verify"
	EventMFADisable EventType = "user.mfa_disable"
)

// ─── Token Events ───

const (
	EventTokenIssued    EventType = "token.issued"
	EventTokenRevoked   EventType = "token.revoked"
	EventTokenRefreshed EventType = "token.refreshed"
)

// ─── Consent Events ───

const (
	EventConsentGranted EventType = "consent.granted"
	EventConsentRevoked EventType = "consent.revoked"
)

// ─── Admin Events ───

const (
	EventUserCreated   EventType = "admin.user_created"
	EventUserUpdated   EventType = "admin.user_updated"
	EventUserDeleted   EventType = "admin.user_deleted"
	EventUserDisabled  EventType = "admin.user_disabled"
	EventUserEnabled   EventType = "admin.user_enabled"
	EventRoleAssigned  EventType = "admin.role_assigned"
	EventRoleRemoved   EventType = "admin.role_removed"
	EventRoleCreated   EventType = "admin.role_created"
	EventRoleUpdated   EventType = "admin.role_updated"
	EventRoleDeleted   EventType = "admin.role_deleted"
	EventClientCreated EventType = "admin.client_created"
	EventClientUpdated EventType = "admin.client_updated"
	EventClientDeleted EventType = "admin.client_deleted"
	EventTenantCreated EventType = "admin.tenant_created"
	EventTenantUpdated EventType = "admin.tenant_updated"
	EventTenantDeleted EventType = "admin.tenant_deleted"
	EventAuditPurged   EventType = "admin.audit_purged"
)

// ─── Cloud Events ───

const (
	EventCloudProxyForward EventType = "cloud.proxy_forward"
	EventCloudProxyBlocked EventType = "cloud.proxy_blocked"
	EventCloudProxyError   EventType = "cloud.proxy_error"
)

// AuditEvent represents a single auditable action in the system.
type AuditEvent struct {
	ID         string         `json:"id"`
	TenantID   string         `json:"tenant_id"`
	Type       EventType      `json:"type"`
	ActorID    string         `json:"actor_id,omitempty"`
	ActorType  string         `json:"actor_type"`
	TargetID   string         `json:"target_id,omitempty"`
	TargetType string         `json:"target_type,omitempty"`
	IPAddress  string         `json:"ip_address"`
	UserAgent  string         `json:"user_agent"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	Result     string         `json:"result"`
	CreatedAt  time.Time      `json:"created_at"`
}

// Result constants.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
	ResultError   = "error"
)

// Actor type constants.
const (
	ActorUser   = "user"
	ActorAdmin  = "admin"
	ActorSystem = "system"
	ActorClient = "client"
	ActorCloud  = "cloud"
)

// Target type constants.
const (
	TargetUser     = "user"
	TargetClient   = "client"
	TargetRole     = "role"
	TargetTenant   = "tenant"
	TargetToken    = "token"
	TargetConsent  = "consent"
	TargetSession  = "session"
	TargetInstance = "instance"
)

// NewEvent creates a new AuditEvent with a generated ID and current timestamp.
func NewEvent(eventType EventType, tenantID string) AuditEvent {
	return AuditEvent{
		ID:        generateID(),
		TenantID:  tenantID,
		Type:      eventType,
		ActorType: ActorSystem,
		Result:    ResultSuccess,
		CreatedAt: time.Now().UTC(),
	}
}

// WithActor sets the actor fields.
func (e AuditEvent) WithActor(actorID, actorType string) AuditEvent {
	e.ActorID = actorID
	e.ActorType = actorType
	return e
}

// WithTarget sets the target fields.
func (e AuditEvent) WithTarget(targetID, targetType string) AuditEvent {
	e.TargetID = targetID
	e.TargetType = targetType
	return e
}

// WithRequest sets IP and User-Agent.
func (e AuditEvent) WithRequest(ip, userAgent string) AuditEvent {
	e.IPAddress = ip
	e.UserAgent = userAgent
	return e
}

// WithResult sets the result field.
func (e AuditEvent) WithResult(result string) AuditEvent {
	e.Result = result
	return e
}

// WithMeta adds a key-value pair to the metadata map.
func (e AuditEvent) WithMeta(key string, value any) AuditEvent {
	// Clone map to preserve value semantics across chained builders.
	cloned := make(map[string]any, len(e.Metadata)+1)
	for k, v := range e.Metadata {
		cloned[k] = v
	}
	cloned[key] = value
	e.Metadata = cloned
	return e
}

// generateID returns a new random UUID v4 string.
// If crypto/rand fails, it falls back to a deterministic UUID v4 derived
// from the current timestamp + monotonic counter so the result is always
// a valid UUID that satisfies both PostgreSQL UUID and MySQL CHAR(36) columns.
func generateID() string {
	var b [16]byte
	if _, err := cryptoRand.Read(b[:]); err != nil {
		// Fallback: build bytes from timestamp + monotonic counter to
		// guarantee a schema-valid UUID even when entropy is unavailable.
		ts := uint64(time.Now().UnixNano())
		seq := fallbackSeq.Add(1)
		b[0] = byte(ts >> 56)
		b[1] = byte(ts >> 48)
		b[2] = byte(ts >> 40)
		b[3] = byte(ts >> 32)
		b[4] = byte(ts >> 24)
		b[5] = byte(ts >> 16)
		b[6] = byte(ts >> 8)
		b[7] = byte(ts)
		b[8] = byte(seq >> 56)
		b[9] = byte(seq >> 48)
		b[10] = byte(seq >> 40)
		b[11] = byte(seq >> 32)
		b[12] = byte(seq >> 24)
		b[13] = byte(seq >> 16)
		b[14] = byte(seq >> 8)
		b[15] = byte(seq)
	}
	// Set UUID v4 variant bits regardless of source.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
