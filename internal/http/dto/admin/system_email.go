package admin

import "time"

// SystemEmailProviderRequest defines write-only payload for global provider update.
type SystemEmailProviderRequest struct {
	Provider  string `json:"provider"`
	FromEmail string `json:"fromEmail"`
	ReplyTo   string `json:"replyTo,omitempty"`
	TimeoutMs int    `json:"timeoutMs,omitempty"`

	APIKey string `json:"apiKey,omitempty"` // write-only
	Domain string `json:"domain,omitempty"`
	Region string `json:"region,omitempty"`

	SMTPHost     string `json:"smtpHost,omitempty"`
	SMTPPort     int    `json:"smtpPort,omitempty"`
	SMTPUsername string `json:"smtpUsername,omitempty"`
	SMTPPassword string `json:"smtpPassword,omitempty"` // write-only
	SMTPUseTLS   bool   `json:"smtpUseTLS,omitempty"`
}

// SystemEmailProviderResponse masks secrets and exposes configured flags only.
type SystemEmailProviderResponse struct {
	Provider         string    `json:"provider,omitempty"`
	FromEmail        string    `json:"fromEmail,omitempty"`
	ReplyTo          string    `json:"replyTo,omitempty"`
	TimeoutMs        int       `json:"timeoutMs,omitempty"`
	Domain           string    `json:"domain,omitempty"`
	Region           string    `json:"region,omitempty"`
	SMTPHost         string    `json:"smtpHost,omitempty"`
	SMTPPort         int       `json:"smtpPort,omitempty"`
	SMTPUsername     string    `json:"smtpUsername,omitempty"`
	SMTPUseTLS       bool      `json:"smtpUseTLS,omitempty"`
	APIKeyConfigured bool      `json:"apiKeyConfigured"`
	UpdatedAt        time.Time `json:"updatedAt,omitempty"`
	UpdatedBy        string    `json:"updatedBy,omitempty"`
}

// SystemEmailGetResponse is returned by GET /v2/admin/system/email.
type SystemEmailGetResponse struct {
	EmailProvider   *SystemEmailProviderResponse `json:"emailProvider,omitempty"`
	EffectiveSource string                       `json:"effectiveSource"` // control_plane | env | none
}

// SystemEmailTestRequest sends a test email with stored or override config.
type SystemEmailTestRequest struct {
	To       string                      `json:"to"`
	Provider *SystemEmailProviderRequest `json:"provider,omitempty"`
}

// SystemEmailTestResponse returns the outcome of the test send.
type SystemEmailTestResponse struct {
	Success  bool   `json:"success"`
	Provider string `json:"provider,omitempty"`
}
