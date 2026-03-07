package admin

import (
	"context"
	"errors"
	"testing"

	"github.com/dropDatabas3/hellojohn/internal/audit"
)

func TestResolveCanonicalTenantID_Success(t *testing.T) {
	t.Parallel()

	dal := &auditServiceDALStub{
		tda: &auditServiceTDAStub{
			slug: "acme",
			id:   "tenant-123",
		},
	}

	tenantID, tenantSlug, err := resolveCanonicalTenantID(context.Background(), dal, "acme")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if tenantID != "tenant-123" {
		t.Fatalf("expected tenant-123, got %q", tenantID)
	}
	if tenantSlug != "acme" {
		t.Fatalf("expected acme, got %q", tenantSlug)
	}
}

func TestEmitAdminEventWithCanonicalTenantRef_FallbackToSystem(t *testing.T) {
	t.Parallel()

	writer := &captureAuditWriter{}
	bus := audit.NewAuditBus(writer)
	bus.Start()
	defer bus.Stop()

	dal := &auditServiceDALStub{err: errors.New("tenant lookup failed")}

	emitAdminEventWithCanonicalTenantRef(
		context.Background(),
		bus,
		dal,
		"acme",
		audit.EventUserUpdated,
		"user-1",
		audit.TargetUser,
		audit.ResultError,
		map[string]any{"reason": "tenant_not_found"},
	)

	bus.Stop()
	events := writer.Snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	evt := events[0]
	if evt.TenantID != audit.ControlPlaneTenantID {
		t.Fatalf("expected tenant %q, got %q", audit.ControlPlaneTenantID, evt.TenantID)
	}
	if got := evt.Metadata["tenant_ref_input"]; got != "acme" {
		t.Fatalf("expected tenant_ref_input=acme, got %v", got)
	}
}

func TestEmitAdminEventWithCanonicalTenantRef_UsesCanonicalTenantID(t *testing.T) {
	t.Parallel()

	writer := &captureAuditWriter{}
	bus := audit.NewAuditBus(writer)
	bus.Start()
	defer bus.Stop()

	dal := &auditServiceDALStub{
		tda: &auditServiceTDAStub{
			slug: "acme",
			id:   "tenant-123",
		},
	}

	emitAdminEventWithCanonicalTenantRef(
		context.Background(),
		bus,
		dal,
		"acme",
		audit.EventClientUpdated,
		"client-a",
		audit.TargetClient,
		audit.ResultSuccess,
		map[string]any{"client_id": "client-a"},
	)

	bus.Stop()
	events := writer.Snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	evt := events[0]
	if evt.TenantID != "tenant-123" {
		t.Fatalf("expected tenant-123, got %q", evt.TenantID)
	}
	if got := evt.Metadata["tenant_slug"]; got != "acme" {
		t.Fatalf("expected tenant_slug=acme, got %v", got)
	}
}
