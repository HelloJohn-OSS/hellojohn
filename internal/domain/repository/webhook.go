package repository

import (
	"context"
	"encoding/json"
	"time"
)

// WebhookConfig representa la configuración de una suscripción a eventos por parte de un inquilino.
type WebhookConfig struct {
	ID        string   `json:"id" yaml:"id"`
	URL       string   `json:"url" yaml:"url"`
	Secret    string   `json:"secret,omitempty" yaml:"-"` // Texto plano, solo útil en la creación. NUNCA se persiste ni expone lueg.
	SecretEnc string   `json:"-" yaml:"secretEnc"`        // Encriptación del secret, seguro para DB/YAML.
	Events    []string `json:"events" yaml:"events"`      // Eventos a los que está subscrito: ["user.login", "*"]
	Enabled   bool     `json:"enabled" yaml:"enabled"`
}

// WebhookDelivery persigue la trazabilidad del estado de una notificación (Outbox pattern).
type WebhookDelivery struct {
	ID            string          `json:"id"`
	WebhookID     string          `json:"webhook_id"`
	EventType     string          `json:"event_type"`
	Payload       json.RawMessage `json:"payload"`
	Status        string          `json:"status"` // "pending", "delivered", "failed", "exhausted"
	Attempts      int             `json:"attempts"`
	LastAttemptAt *time.Time      `json:"last_attempt_at,omitempty"`
	NextRetryAt   *time.Time      `json:"next_retry_at,omitempty"`
	HTTPStatus    *int            `json:"http_status,omitempty"`
	ResponseBody  *string         `json:"response_body,omitempty"` // Truncado a 512 bytes
	CreatedAt     time.Time       `json:"created_at"`
}

// WebhookDeliveryFilter encapsula los parámetros de filtrado para listado de entregas.
// Todos los campos son opcionales. Si un campo es zero value, no se aplica ese filtro.
type WebhookDeliveryFilter struct {
	From   time.Time // created_at >= From (si !From.IsZero())
	To     time.Time // created_at <= To (si !To.IsZero())
	Result string    // status exacto: "pending"|"delivered"|"failed"|"exhausted"|""
	Event  string    // event_type exacto, case-sensitive, "" = sin filtro
}

// WebhookRepository define las operaciones de persistencia del sistema de Webhooks (patrón Outbox).
// Esta interfaz será implementada por los adaptadores específicos de cada driver SQL a nivel de inquilino.
type WebhookRepository interface {
	// InsertDelivery encola un nuevo mensaje en la tabla webhook_delivery con estado 'pending'.
	InsertDelivery(ctx context.Context, delivery *WebhookDelivery) error

	// FetchPending extrae N registros pendientes de envío para ser procesados, asegurando bloqueos para evitar dobles envíos.
	// En PostgreSQL usar FOR UPDATE SKIP LOCKED. En MySQL usar bloqueo equivalente.
	FetchPending(ctx context.Context, limit int) ([]*WebhookDelivery, error)

	// UpdateDeliveryStatus actualiza el estado, reintentos, y payload del intento HTTP de una entrega procesada.
	UpdateDeliveryStatus(ctx context.Context, id string, status string, attempts int, nextRetry, lastAttempt *time.Time, httpStatus *int, responseBody *string) error

	// ListDeliveries retorna hasta limit+1 entregas para poder determinar has_more.
	ListDeliveries(ctx context.Context, webhookID string, limit, offset int, filter WebhookDeliveryFilter) ([]*WebhookDelivery, error)
}
