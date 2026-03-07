package admin

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/controlplane"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"github.com/dropDatabas3/hellojohn/internal/security/secretbox"
	tokens "github.com/dropDatabas3/hellojohn/internal/security/token"
	"github.com/google/uuid"
)

const errTenantRequired = "tenant is required"
const errUpdateTenantFailed = "Failed to update tenant settings"

// WebhooksController maneja las rutas de configuracion de webhooks por tenant bajo /v2/admin/tenants/{tid}/webhooks.
type WebhooksController struct {
	controlPlane controlplane.Service
}

// NewWebhooksController retorna una nueva instancia.
func NewWebhooksController(cp controlplane.Service) *WebhooksController {
	return &WebhooksController{controlPlane: cp}
}

// isSSRFVulnerable determina si una URL objetivo asoma riesgos de Server-Side Request Forgery.
func isSSRFVulnerable(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return true // Si no parsea, bloqueamos
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return true // Sólo protocolos web permitidos
	}

	host := parsed.Hostname()
	ips, err := net.LookupIP(host)
	if err != nil {
		// Fallback: si host es ip directo
		if ip := net.ParseIP(host); ip != nil {
			ips = []net.IP{ip}
		} else {
			return true // No resuelve, bloqueamos ante la duda
		}
	}

	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return true
		}
	}
	return false
}

// List maneja GET /v2/admin/tenants/{tenant_id}/webhooks
func (c *WebhooksController) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("WebhooksController.List"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(errTenantRequired))
		return
	}

	settings := tda.Settings()
	webhooks := settings.Webhooks

	if webhooks == nil {
		webhooks = []repository.WebhookConfig{}
	}

	log.Debug("webhooks listed", logger.String("tenant_id", tda.ID()))
	writeJSON(w, http.StatusOK, map[string]any{"webhooks": webhooks})
}

// Create maneja POST /v2/admin/tenants/{tenant_id}/webhooks
func (c *WebhooksController) Create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("WebhooksController.Create"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(errTenantRequired))
		return
	}

	var req dto.CreateWebhookRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	if req.URL == "" || len(req.Events) == 0 {
		httperrors.WriteError(w, httperrors.ErrMissingFields.WithDetail("url and events are required"))
		return
	}

	if isSSRFVulnerable(req.URL) {
		log.Warn("SSRF attempt blocked", logger.String("url", req.URL))
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("Invalid or unsafe webhook URL provided"))
		return
	}

	// Secret generation
	rawSecret, err := tokens.GenerateOpaqueToken(32)
	if err != nil {
		log.Error("Failed to generate hook secret", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	// Secret encryption via internal helper
	encSecret, err := secretbox.Encrypt(rawSecret)
	if err != nil {
		log.Error("Failed to encrypt hook secret", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	wh := repository.WebhookConfig{
		ID:        "wh_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12],
		URL:       req.URL,
		Secret:    rawSecret, // Texto plano que sólo viajará en este request mapping.
		SecretEnc: encSecret, // Encriptación en base de datos.
		Events:    req.Events,
		Enabled:   req.Enabled,
	}

	settings := tda.Settings()
	if settings.Webhooks == nil {
		settings.Webhooks = []repository.WebhookConfig{}
	}
	settings.Webhooks = append(settings.Webhooks, wh)

	if err := c.controlPlane.UpdateTenantSettings(ctx, tda.Slug(), settings); err != nil {
		log.Error(errUpdateTenantFailed, logger.Err(err))
		var appErr *httperrors.AppError
		if errors.As(err, &appErr) {
			httperrors.WriteError(w, appErr)
		} else {
			httperrors.WriteError(w, httperrors.ErrInternalServerError)
		}
		return
	}

	log.Info("Webhook created", logger.String("webhook_id", wh.ID), logger.String("tenant_id", tda.ID()))
	writeJSON(w, http.StatusCreated, wh)
}

// extractWebhookIDFromPath extracts the webhook ID assuming the route is /.../webhooks/{webhookId}
func extractWebhookIDFromPath(path string) string {
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}

// Update maneja PUT /v2/admin/tenants/{tenant_id}/webhooks/{webhookId}
func (c *WebhooksController) Update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("WebhooksController.Update"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(errTenantRequired))
		return
	}

	hookID := extractWebhookIDFromPath(r.URL.Path)

	var req dto.UpdateWebhookRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	if req.URL != nil && isSSRFVulnerable(*req.URL) {
		log.Warn("SSRF attempt blocked during update", logger.String("url", *req.URL))
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("Invalid or unsafe webhook URL provided"))
		return
	}

	settings := tda.Settings()
	var updatedHook *repository.WebhookConfig
	var found bool

	for i, hook := range settings.Webhooks {
		if hook.ID == hookID {
			if req.URL != nil {
				settings.Webhooks[i].URL = *req.URL
			}
			if req.Events != nil {
				settings.Webhooks[i].Events = *req.Events
			}
			if req.Enabled != nil {
				settings.Webhooks[i].Enabled = *req.Enabled
			}
			updatedHook = &settings.Webhooks[i]
			found = true
			break
		}
	}

	if !found {
		httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("webhook not found"))
		return
	}

	if err := c.controlPlane.UpdateTenantSettings(ctx, tda.Slug(), settings); err != nil {
		log.Error(errUpdateTenantFailed, logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, updatedHook)
}

// Delete maneja DELETE /v2/admin/tenants/{tenant_id}/webhooks/{webhookId}
func (c *WebhooksController) Delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("WebhooksController.Delete"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(errTenantRequired))
		return
	}

	hookID := extractWebhookIDFromPath(r.URL.Path)
	settings := tda.Settings()

	var newHooks []repository.WebhookConfig
	var found bool
	for _, hook := range settings.Webhooks {
		if hook.ID != hookID {
			newHooks = append(newHooks, hook)
		} else {
			found = true
		}
	}

	if !found {
		httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("webhook not found"))
		return
	}

	settings.Webhooks = newHooks

	if err := c.controlPlane.UpdateTenantSettings(ctx, tda.Slug(), settings); err != nil {
		log.Error(errUpdateTenantFailed, logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// extractWebhookSubPathID extrae el webhookId de rutas con sub-paths como:
//
//	/v2/admin/tenants/{tid}/webhooks/{webhookId}/deliveries
//	/v2/admin/tenants/{tid}/webhooks/{webhookId}/test
//
// Retorna el webhookId (penúltimo segmento del path).
func extractWebhookSubPathID(path string) string {
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")
	// El webhookId está en la posición len-2 cuando hay sub-path
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return ""
}

// ListDeliveries maneja GET /v2/admin/tenants/{tenant_id}/webhooks/{webhookId}/deliveries
// Requiere que el tenant tenga base de datos configurada.
func (c *WebhooksController) ListDeliveries(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("WebhooksController.ListDeliveries"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(errTenantRequired))
		return
	}

	// Delivery history vive en la base de datos del tenant.
	if err := tda.RequireDB(); err != nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant has no database configured"))
		return
	}

	webhookID := extractWebhookSubPathID(r.URL.Path)
	if webhookID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("webhookId is required"))
		return
	}

	q := r.URL.Query()

	// limit — default 25, max 100
	limit := 25
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invalid limit"))
			return
		}
		if n > 100 {
			n = 100
		}
		limit = n
	}

	// offset — default 0
	offset := 0
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("invalid offset"))
			return
		}
		offset = n
	}

	var filter repository.WebhookDeliveryFilter

	// from: RFC3339
	if v := q.Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("from must be a valid RFC3339 datetime"))
			return
		}
		filter.From = t
	}

	// to: RFC3339
	if v := q.Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("to must be a valid RFC3339 datetime"))
			return
		}
		filter.To = t
	}

	// Validar que from <= to si ambos están presentes.
	if !filter.From.IsZero() && !filter.To.IsZero() && filter.From.After(filter.To) {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("from must be before or equal to to"))
		return
	}

	// Validar rango máximo de 90 días para evitar abuso.
	if !filter.From.IsZero() && !filter.To.IsZero() {
		if filter.To.Sub(filter.From) > 90*24*time.Hour {
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("date range cannot exceed 90 days"))
			return
		}
	}

	// result: solo valores del enum permitido
	if v := q.Get("result"); v != "" {
		validResults := map[string]bool{
			"pending":   true,
			"delivered": true,
			"failed":    true,
			"exhausted": true,
		}
		if !validResults[v] {
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("result must be one of: pending, delivered, failed, exhausted"))
			return
		}
		filter.Result = v
	}

	// event: exacto y longitud razonable
	if v := q.Get("event"); v != "" {
		v = strings.TrimSpace(v)
		if len(v) > 100 {
			httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("event must be 100 characters or less"))
			return
		}
		filter.Event = v
	}

	deliveries, err := tda.Webhooks().ListDeliveries(ctx, webhookID, limit, offset, filter)
	if err != nil {
		log.Error("failed to list webhook deliveries", logger.Err(err), logger.String("webhook_id", webhookID))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	// Determinar has_more y recortar al límite real.
	hasMore := len(deliveries) > limit
	if hasMore {
		deliveries = deliveries[:limit]
	}

	// Mapear a DTOs HTTP (serialización segura de punteros de tiempo)
	items := make([]dto.WebhookDeliveryResponse, 0, len(deliveries))
	for _, d := range deliveries {
		item := dto.WebhookDeliveryResponse{
			ID:           d.ID,
			WebhookID:    d.WebhookID,
			EventType:    d.EventType,
			Status:       d.Status,
			Attempts:     d.Attempts,
			HTTPStatus:   d.HTTPStatus,
			ResponseBody: d.ResponseBody,
			CreatedAt:    d.CreatedAt.UTC().Format(time.RFC3339),
		}
		if d.LastAttemptAt != nil {
			s := d.LastAttemptAt.UTC().Format(time.RFC3339)
			item.LastAttemptAt = &s
		}
		if d.NextRetryAt != nil {
			s := d.NextRetryAt.UTC().Format(time.RFC3339)
			item.NextRetryAt = &s
		}
		items = append(items, item)
	}

	log.Debug("webhook deliveries listed",
		logger.String("tenant_id", tda.ID()),
		logger.String("webhook_id", webhookID),
		logger.Int("count", len(items)),
	)

	writeJSON(w, http.StatusOK, dto.ListDeliveriesResponse{
		Deliveries: items,
		Limit:      limit,
		Offset:     offset,
		HasMore:    hasMore,
	})
}

// TestHandshake maneja POST /v2/admin/tenants/{tenant_id}/webhooks/{webhookId}/test
// Encola un evento ficticio "system.ping" para verificar conectividad del endpoint.
// Requiere que el tenant tenga base de datos configurada.
func (c *WebhooksController) TestHandshake(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("WebhooksController.TestHandshake"))

	tda := mw.GetTenant(ctx)
	if tda == nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(errTenantRequired))
		return
	}

	// El ping encola en la tabla de deliveries del tenant.
	if err := tda.RequireDB(); err != nil {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("tenant has no database configured"))
		return
	}

	webhookID := extractWebhookSubPathID(r.URL.Path)
	if webhookID == "" {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail("webhookId is required"))
		return
	}

	// Verificar que el webhook existe en la configuración del tenant.
	settings := tda.Settings()
	var found bool
	for _, wh := range settings.Webhooks {
		if wh.ID == webhookID {
			found = true
			break
		}
	}
	if !found {
		httperrors.WriteError(w, httperrors.ErrNotFound.WithDetail("webhook not found"))
		return
	}

	// Construir payload mínimo para el ping.
	now := time.Now().UTC()
	pingPayload := []byte(`{"event":"system.ping","source":"admin_test","timestamp":"` + now.Format(time.RFC3339) + `"}`)

	deliveryID := uuid.NewString()
	delivery := &repository.WebhookDelivery{
		ID:        deliveryID,
		WebhookID: webhookID,
		EventType: "system.ping",
		Payload:   pingPayload,
		Status:    "pending",
		Attempts:  0,
		CreatedAt: now,
	}

	if err := tda.Webhooks().InsertDelivery(ctx, delivery); err != nil {
		log.Error("failed to enqueue test delivery", logger.Err(err), logger.String("webhook_id", webhookID))
		httperrors.WriteError(w, httperrors.ErrInternalServerError)
		return
	}

	log.Info("webhook test ping enqueued",
		logger.String("tenant_id", tda.ID()),
		logger.String("webhook_id", webhookID),
		logger.String("delivery_id", deliveryID),
	)

	writeJSON(w, http.StatusAccepted, dto.TestWebhookResponse{
		Enqueued:   true,
		DeliveryID: deliveryID,
	})
}
