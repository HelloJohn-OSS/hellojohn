package webhook

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/google/uuid"
)

// WebhookInserter define la operación necesaria para persistir en outbox
type WebhookInserter interface {
	InsertDelivery(ctx context.Context, delivery *repository.WebhookDelivery) error
}

// TenantResolver mapea la abstracción de búsqueda para desacoplar el DAL (evita import cycle)
type TenantResolver interface {
	Resolve(ctx context.Context, tenantID string) ([]repository.WebhookConfig, WebhookInserter, error)
}

// Writer implements audit.Writer and routes audit events to tenant webhooks via Outbox.
type Writer struct {
	Resolver TenantResolver
}

// Write processes a batch of audit events asynchronously.
func (w *Writer) Write(ctx context.Context, events []audit.AuditEvent) error {
	for _, evt := range events {
		if evt.TenantID == "" {
			continue
		}

		configs, inserter, err := w.Resolver.Resolve(ctx, evt.TenantID)
		if err != nil {
			log.Printf("WARN: WebhookWriter failed to resolve tenant %s: %v", evt.TenantID, err)
			continue
		}

		if len(configs) == 0 || inserter == nil {
			continue
		}

		var payload []byte

		for _, whCfg := range configs {
			if !whCfg.Enabled {
				continue
			}

			matched := false
			for _, allowedEvent := range whCfg.Events {
				if allowedEvent == "*" || allowedEvent == string(evt.Type) {
					matched = true
					break
				}
			}

			if matched {
				if payload == nil {
					p, err := json.Marshal(evt)
					if err != nil {
						log.Printf("WARN: WebhookWriter failed to marshal event %s for tenant %s: %v", evt.Type, evt.TenantID, err)
						break
					}
					payload = p
				}

				now := time.Now().UTC()
				deliveryID := uuid.NewString()

				delivery := &repository.WebhookDelivery{
					ID:          deliveryID,
					WebhookID:   whCfg.ID,
					EventType:   string(evt.Type),
					Payload:     payload,
					Status:      "pending",
					Attempts:    0,
					NextRetryAt: &now,
					CreatedAt:   now,
				}

				if err := inserter.InsertDelivery(ctx, delivery); err != nil {
					log.Printf("WARN: WebhookWriter failed to insert delivery %s (webhook: %s, tenant: %s): %v", deliveryID, whCfg.ID, evt.TenantID, err)
				}
			}
		}
	}

	return nil
}
