package admin

import (
	"context"
	"sync"
	"testing"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	"github.com/dropDatabas3/hellojohn/internal/jwt"
)

type captureAuditWriter struct {
	mu     sync.Mutex
	events []audit.AuditEvent
}

func (w *captureAuditWriter) Write(ctx context.Context, events []audit.AuditEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, events...)
	return nil
}

func (w *captureAuditWriter) Snapshot() []audit.AuditEvent {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]audit.AuditEvent, len(w.events))
	copy(out, w.events)
	return out
}

func TestEmitAdminEvent_UsesAdminClaimsAndRequestContext(t *testing.T) {
	t.Parallel()

	writer := &captureAuditWriter{}
	bus := audit.NewAuditBus(writer)
	bus.Start()

	ctx := context.Background()
	ctx = mw.SetAdminClaims(ctx, &jwt.AdminAccessClaims{
		AdminID:   "admin-1",
		AdminType: "global",
	})
	ctx = mw.SetClientIP(ctx, "10.0.0.1")
	ctx = mw.SetUserAgent(ctx, "agent-test")

	emitAdminEvent(
		ctx,
		bus,
		"tenant-a",
		audit.EventUserUpdated,
		"user-1",
		audit.TargetUser,
		audit.ResultSuccess,
		map[string]any{"reason": "manual_update"},
	)

	bus.Stop()

	events := writer.Snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	got := events[0]
	if got.ActorID != "admin-1" || got.ActorType != audit.ActorAdmin {
		t.Fatalf("unexpected actor: %+v", got)
	}
	if got.IPAddress != "10.0.0.1" || got.UserAgent != "agent-test" {
		t.Fatalf("unexpected request context in event: %+v", got)
	}
	if got.Result != audit.ResultSuccess {
		t.Fatalf("unexpected result: %s", got.Result)
	}
}
