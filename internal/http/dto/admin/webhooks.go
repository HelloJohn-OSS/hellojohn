package admin

type CreateWebhookRequest struct {
	URL     string   `json:"url"`
	Events  []string `json:"events"`
	Enabled bool     `json:"enabled"`
}

type UpdateWebhookRequest struct {
	URL     *string   `json:"url"`
	Events  *[]string `json:"events"`
	Enabled *bool     `json:"enabled"`
}

// WebhookDeliveryResponse es la representación HTTP de un intento de entrega.
type WebhookDeliveryResponse struct {
	ID            string  `json:"id"`
	WebhookID     string  `json:"webhook_id"`
	EventType     string  `json:"event_type"`
	Status        string  `json:"status"`
	Attempts      int     `json:"attempts"`
	HTTPStatus    *int    `json:"http_status,omitempty"`
	ResponseBody  *string `json:"response_body,omitempty"`
	LastAttemptAt *string `json:"last_attempt_at,omitempty"` // RFC3339 o nil
	NextRetryAt   *string `json:"next_retry_at,omitempty"`   // RFC3339 o nil
	CreatedAt     string  `json:"created_at"`                // RFC3339
}

// ListDeliveriesResponse envuelve el listado paginado de entregas.
type ListDeliveriesResponse struct {
	Deliveries []WebhookDeliveryResponse `json:"deliveries"`
	Limit      int                       `json:"limit"`
	Offset     int                       `json:"offset"`
	HasMore    bool                      `json:"has_more"` // true si hay más páginas disponibles
}

// TestWebhookResponse confirma que el ping fue encolado.
type TestWebhookResponse struct {
	Enqueued   bool   `json:"enqueued"`
	DeliveryID string `json:"delivery_id"`
}
