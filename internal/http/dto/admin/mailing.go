package admin

// SendTestEmailRequest is the request for POST /v2/admin/mailing/test.
type SendTestEmailRequest struct {
	To           string        `json:"to"`
	SMTPOverride *SMTPOverride `json:"smtp,omitempty"` // Optional SMTP config override
}

// SMTPOverride contains SMTP settings to test.
type SMTPOverride struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	FromEmail string `json:"from_email"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	UseTLS    bool   `json:"use_tls,omitempty"`
}

// SendTestEmailResponse is the response for successful email send.
type SendTestEmailResponse struct {
	Status string `json:"status"`
	SentTo string `json:"sent_to"`
}
