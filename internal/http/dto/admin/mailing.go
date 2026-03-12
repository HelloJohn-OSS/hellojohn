package admin

// SendTestEmailRequest is the request for POST /v2/admin/mailing/test.
type SendTestEmailRequest struct {
	To           string            `json:"to"`
	SMTPOverride *SMTPOverride     `json:"smtp,omitempty"`
	Provider     *ProviderOverride `json:"provider,omitempty"`
}

// SMTPOverride contains SMTP settings to test.
type SMTPOverride struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	FromEmail string `json:"fromEmail"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	UseTLS    bool   `json:"useTLS,omitempty"`
}

// ProviderOverride allows sending a test email with a provider override
// without persisting tenant settings.
type ProviderOverride struct {
	Kind      string `json:"kind"`
	APIKey    string `json:"apiKey,omitempty"` // write-only
	FromEmail string `json:"fromEmail"`
	ReplyTo   string `json:"replyTo,omitempty"`
	Domain    string `json:"domain,omitempty"`
	Region    string `json:"region,omitempty"`
	TimeoutMs int    `json:"timeoutMs,omitempty"`
}

// SendTestEmailResponse is the response for successful email send.
type SendTestEmailResponse struct {
	Status string `json:"status"`
	SentTo string `json:"sent_to"`
}
