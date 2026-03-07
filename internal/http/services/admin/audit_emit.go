package admin

import (
	"context"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
)

// emitAdminEvent emits an admin audit event with a consistent actor/request envelope.
func emitAdminEvent(
	ctx context.Context,
	bus *audit.AuditBus,
	tenantID string,
	eventType audit.EventType,
	targetID string,
	targetType string,
	result string,
	meta map[string]any,
) {
	if bus == nil || strings.TrimSpace(tenantID) == "" {
		return
	}

	evt := audit.NewEvent(eventType, tenantID).
		WithRequest(mw.GetClientIP(ctx), mw.GetUserAgent(ctx))

	if strings.TrimSpace(result) != "" {
		evt = evt.WithResult(result)
	}

	if strings.TrimSpace(targetID) != "" && strings.TrimSpace(targetType) != "" {
		evt = evt.WithTarget(targetID, targetType)
	}

	if claims := mw.GetAdminClaims(ctx); claims != nil && strings.TrimSpace(claims.AdminID) != "" {
		evt = evt.WithActor(claims.AdminID, audit.ActorAdmin)
		if strings.TrimSpace(claims.AdminType) != "" {
			evt = evt.WithMeta("admin_type", claims.AdminType)
		}
	} else {
		evt = evt.WithActor("", audit.ActorSystem)
	}

	for k, v := range meta {
		evt = evt.WithMeta(k, v)
	}

	bus.Emit(evt)
}
