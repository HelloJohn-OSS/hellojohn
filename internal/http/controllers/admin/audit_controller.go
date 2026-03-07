package admin

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	jwtx "github.com/dropDatabas3/hellojohn/internal/jwt"
)

// AuditController handles audit log admin endpoints.
type AuditController struct {
	service svc.AuditService
}

// NewAuditController creates a new AuditController.
func NewAuditController(service svc.AuditService) *AuditController {
	return &AuditController{service: service}
}

// List handles GET /v2/admin/tenants/{tenant_id}/audit-logs
func (c *AuditController) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrNotFound)
		return
	}

	adminClaims := mw.GetAdminClaims(ctx)
	if !canReadAudit(adminClaims) {
		httperrors.WriteError(w, httperrors.ErrForbidden.WithDetail("audit:read permission required"))
		return
	}

	q := r.URL.Query()

	filter := repository.AuditFilter{
		EventType: q.Get("event_type"),
		ActorID:   q.Get("actor_id"),
		TargetID:  q.Get("target_id"),
		Result:    q.Get("result"),
	}

	// Pagination — reject malformed values instead of silently ignoring them
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			httperrors.WriteError(w, httperrors.ErrBadRequest)
			return
		}
		filter.Limit = n
	}
	if filter.Limit == 0 {
		filter.Limit = 50
	} else if filter.Limit > 100 {
		filter.Limit = 100
	}

	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			httperrors.WriteError(w, httperrors.ErrBadRequest)
			return
		}
		filter.Offset = n
	}

	// Time range — reject malformed dates
	if v := q.Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			httperrors.WriteError(w, httperrors.ErrBadRequest)
			return
		}
		filter.From = t
	}
	if v := q.Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			httperrors.WriteError(w, httperrors.ErrBadRequest)
			return
		}
		filter.To = t
	}

	events, total, err := c.service.List(ctx, tda.Slug(), filter)
	if err != nil {
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"data":   events,
		"total":  total,
		"limit":  filter.Limit,
		"offset": filter.Offset,
	}); err != nil {
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}
}

// Get handles GET /v2/admin/tenants/{tenant_id}/audit-logs/{auditId}
func (c *AuditController) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrNotFound)
		return
	}

	adminClaims := mw.GetAdminClaims(ctx)
	if !canReadAudit(adminClaims) {
		httperrors.WriteError(w, httperrors.ErrForbidden.WithDetail("audit:read permission required"))
		return
	}

	auditID := r.PathValue("auditId")
	if auditID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest)
		return
	}

	event, err := c.service.GetByID(ctx, tda.Slug(), auditID)
	if err != nil {
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}
	if event == nil {
		httperrors.WriteError(w, httperrors.ErrNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(event); err != nil {
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}
}

// Purge handles POST /v2/admin/tenants/{tenant_id}/audit-logs/purge
func (c *AuditController) Purge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrNotFound)
		return
	}

	adminClaims := mw.GetAdminClaims(ctx)
	if !canPurgeAudit(adminClaims) {
		httperrors.WriteError(w, httperrors.ErrForbidden.WithDetail("audit:purge permission required"))
		return
	}

	var req struct {
		Before string `json:"before"` // RFC3339
		Days   int    `json:"days"`   // Alternative: purge older than N days
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	var before time.Time
	if req.Before != "" {
		t, err := time.Parse(time.RFC3339, req.Before)
		if err != nil {
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("before must be RFC3339"))
			return
		}
		before = t
	} else if req.Days > 0 {
		before = time.Now().UTC().AddDate(0, 0, -req.Days)
	} else {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("either before (RFC3339) or days (>0) is required"))
		return
	}

	deleted, err := c.service.Purge(ctx, tda.Slug(), before)
	if err != nil {
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"deleted": deleted,
		"before":  before.Format(time.RFC3339),
	}); err != nil {
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}
}

// canReadAudit enforces audit:read permission.
// Tenant boundary is enforced separately by RequireAdminTenantAccess middleware.
func canReadAudit(claims *jwtx.AdminAccessClaims) bool {
	return hasAuditPerm(claims, "audit:read")
}

// canPurgeAudit enforces explicit purge permission.
// Purge is restricted via explicit audit:purge permission.
func canPurgeAudit(claims *jwtx.AdminAccessClaims) bool {
	return hasAuditPerm(claims, "audit:purge")
}

func hasAuditPerm(claims *jwtx.AdminAccessClaims, want string) bool {
	if claims == nil {
		return false
	}
	want = strings.ToLower(strings.TrimSpace(want))
	if want == "" {
		return false
	}
	for _, p := range claims.Perms {
		perm := strings.ToLower(strings.TrimSpace(p))
		if perm == want || perm == "*" || perm == "audit:*" {
			return true
		}
	}
	return false
}
