package webhook

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/controlplane"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/security/secretbox"
	"github.com/dropDatabas3/hellojohn/internal/store"
)

// StartWorker inicia una Goroutine infinita atada al ciclo de vida del Contexto
// provisto. Esta función despachará los eventos encolados en el Outbox transaccional (webhook_delivery)
// por todo Tenant de forma persistente.
func StartWorker(ctx context.Context, cPlane controlplane.Service, dal store.DataAccessLayer) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	log.Println("🚀 Webhook Delivery Worker Started...")

	for {
		select {
		case <-ctx.Done():
			log.Println("🛑 Webhook Delivery Worker shutting down.")
			return
		case <-ticker.C:
			processAllTenants(ctx, cPlane, dal)
		}
	}
}

func processAllTenants(ctx context.Context, cPlane controlplane.Service, dal store.DataAccessLayer) {
	// Prevenir un bloqueo absoluto congelando el ticker general
	ctxTick, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	tenants, err := cPlane.ListTenants(ctxTick)
	if err != nil {
		log.Printf("Worker error fetching tenants: %v", err)
		return
	}

	for _, tenant := range tenants {
		tda, err := dal.ForTenant(ctxTick, tenant.ID)
		if err != nil {
			continue
		}

		// Únicamente si el Tenant tiene soporte de Base Transaccional Activa
		if err := tda.RequireDB(); err != nil {
			continue
		}

		// Extraer pending deliveries, se bloquean las filas en bases que soportan FOR UPDATE SKIP LOCKED
		deliveries, err := tda.Webhooks().FetchPending(ctxTick, 50)
		if err != nil || len(deliveries) == 0 {
			continue
		}

		settings := tda.Settings()
		if settings == nil {
			continue
		}

		// Build map para búsquedas O(1) de Configs y URLs
		whMap := make(map[string]repository.WebhookConfig)
		for _, wh := range settings.Webhooks {
			whMap[wh.ID] = wh
		}

		for _, delivery := range deliveries {
			whCfg, ok := whMap[delivery.WebhookID]
			if !ok || !whCfg.Enabled {
				// El Webhook ha sido eliminado por el admin o deshabilitado explícitamente.
				// Para evitar un cuello de botella infinito, forzamos Exhausted sin retries extra.
				now := time.Now()
				status := 0
				_ = tda.Webhooks().UpdateDeliveryStatus(ctxTick, delivery.ID, "exhausted", delivery.Attempts, nil, &now, &status, nil)
				continue
			}

			processDelivery(ctxTick, delivery, whCfg, tda)
		}
	}
}

func processDelivery(ctx context.Context, delivery *repository.WebhookDelivery, whCfg repository.WebhookConfig, tda store.TenantDataAccess) {
	// Desencriptación del secreto en memoria volátil (solo mientras viva este Request)
	rawSecret, err := secretbox.Decrypt(whCfg.SecretEnc)
	if err != nil {
		log.Printf("Worker decrypt error for webhook %s (tenant: %s): %v", whCfg.ID, tda.Slug(), err)
		now := time.Now()
		status := 0
		_ = tda.Webhooks().UpdateDeliveryStatus(ctx, delivery.ID, "exhausted", delivery.Attempts, nil, &now, &status, nil)
		return
	}

	ts := time.Now().UTC().Unix()
	signature := Sign(delivery.Payload, rawSecret, ts)

	// Leak Prevention Categórica ante Demoras provocadas por clientes (10 segundos firmes)
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "POST", whCfg.URL, bytes.NewBuffer(delivery.Payload))
	if err != nil {
		handleDeliveryFailure(ctx, delivery, tda, err.Error(), 0)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "HelloJohn-Webhooks/1.0")

	// Injecting HelloJohn Auth Headers (HMAC y Trazabilidad)
	req.Header.Set("X-HelloJohn-Event", delivery.EventType)
	req.Header.Set("X-HelloJohn-Delivery-ID", delivery.ID)
	req.Header.Set("X-HelloJohn-Signature", fmt.Sprintf("t=%d,v1=%s", ts, signature))

	now := time.Now()

	res, err := client.Do(req)
	if err != nil {
		handleDeliveryFailure(ctx, delivery, tda, err.Error(), 0)
		return
	}
	defer res.Body.Close()

	// Mitigación de Overflows/Memory Bloat en caso que el Endpoint escupiera Basura gigante.
	bodyBytes, _ := io.ReadAll(io.LimitReader(res.Body, 512))
	bodyStr := string(bodyBytes)
	statusCode := res.StatusCode

	if statusCode >= 200 && statusCode < 300 {
		_ = tda.Webhooks().UpdateDeliveryStatus(ctx, delivery.ID, "delivered", delivery.Attempts+1, nil, &now, &statusCode, &bodyStr)
	} else {
		// Cayó en la zona oscura del Layer 4 o 5 (e.g. 400s o 500s crasheados).
		handleDeliveryFailure(ctx, delivery, tda, bodyStr, statusCode)
	}
}

func handleDeliveryFailure(ctx context.Context, delivery *repository.WebhookDelivery, tda store.TenantDataAccess, responseBody string, statusCode int) {
	now := time.Now()
	// Contablemente, sumamos el intento al que fracasamos recién.
	attempts := delivery.Attempts + 1

	var nextRetry *time.Time
	status := "failed"

	// Matemática exponencial a 5 Capas.
	if attempts >= 5 {
		status = "exhausted"
	} else {
		nextRetry = calculateNextRetry(attempts)
		if nextRetry == nil {
			status = "exhausted"
		}
	}

	var bodyPtr *string
	if responseBody != "" {
		bodyPtr = &responseBody
	}

	var codePtr *int
	if statusCode > 0 {
		codePtr = &statusCode
	}

	_ = tda.Webhooks().UpdateDeliveryStatus(ctx, delivery.ID, status, attempts, nextRetry, &now, codePtr, bodyPtr)
}

func calculateNextRetry(attempts int) *time.Time {
	var duration time.Duration
	switch attempts {
	case 1:
		duration = 30 * time.Second
	case 2:
		duration = 5 * time.Minute
	case 3:
		duration = 30 * time.Minute
	case 4:
		duration = 2 * time.Hour
	default:
		return nil
	}
	t := time.Now().Add(duration)
	return &t
}
