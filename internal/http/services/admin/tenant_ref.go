package admin

import (
	"context"
	"fmt"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

func cloneAuditMeta(meta map[string]any) map[string]any {
	if len(meta) == 0 {
		return map[string]any{}
	}
	out := make(map[string]any, len(meta)+2)
	for k, v := range meta {
		out[k] = v
	}
	return out
}

// resolveCanonicalTenantID resolves a tenant reference (slug or ID) to the canonical immutable tenant ID.
func resolveCanonicalTenantID(ctx context.Context, dal store.DataAccessLayer, slugOrID string) (tenantID string, tenantSlug string, err error) {
	tenantRef := strings.TrimSpace(slugOrID)
	if tenantRef == "" {
		return "", "", fmt.Errorf("tenant reference is empty")
	}
	if dal == nil {
		return "", "", fmt.Errorf("tenant data access layer is nil")
	}

	tda, err := dal.ForTenant(ctx, tenantRef)
	if err != nil {
		return "", "", err
	}

	tenantID = strings.TrimSpace(tda.ID())
	tenantSlug = strings.TrimSpace(tda.Slug())
	if tenantID == "" {
		return "", tenantSlug, fmt.Errorf("tenant canonical id is empty")
	}
	return tenantID, tenantSlug, nil
}

// emitAdminEventWithCanonicalTenantRef emits admin events with canonical tenant_id.
// If tenant resolution fails, it emits to control-plane tenant "system" and enriches metadata
// with the unresolved reference for traceability.
func emitAdminEventWithCanonicalTenantRef(
	ctx context.Context,
	bus *audit.AuditBus,
	dal store.DataAccessLayer,
	tenantRef string,
	eventType audit.EventType,
	targetID string,
	targetType string,
	result string,
	meta map[string]any,
) {
	enrichedMeta := cloneAuditMeta(meta)
	tenantRef = strings.TrimSpace(tenantRef)

	tenantID, tenantSlug, err := resolveCanonicalTenantID(ctx, dal, tenantRef)
	if err != nil {
		if tenantRef != "" {
			enrichedMeta["tenant_ref_input"] = tenantRef
		}
		if tenantSlug != "" {
			enrichedMeta["tenant_slug"] = tenantSlug
		}

		emitAdminEvent(
			ctx,
			bus,
			audit.ControlPlaneTenantID,
			eventType,
			targetID,
			targetType,
			result,
			enrichedMeta,
		)
		return
	}

	if tenantSlug != "" && !strings.EqualFold(tenantSlug, tenantID) {
		enrichedMeta["tenant_slug"] = tenantSlug
	}

	emitAdminEvent(
		ctx,
		bus,
		tenantID,
		eventType,
		targetID,
		targetType,
		result,
		enrichedMeta,
	)
}
