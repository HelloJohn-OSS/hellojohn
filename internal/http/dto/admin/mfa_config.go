package admin

// MFAConfigResponse is returned by GET /v2/admin/tenants/{tenant_id}/mfa/config.
type MFAConfigResponse struct {
	TOTP     MFATOTPConfig     `json:"totp"`
	SMS      MFASMSConfigInfo  `json:"sms"`
	Adaptive MFAAdaptiveConfig `json:"adaptive"`
}

type MFATOTPConfig struct {
	Issuer         string `json:"issuer"`
	IsGlobal       bool   `json:"is_global"`
	Window         int    `json:"window"`
	WindowIsGlobal bool   `json:"window_is_global"`
}

// MFASMSConfigInfo never returns credentials, only operational metadata.
type MFASMSConfigInfo struct {
	Provider       string `json:"provider"` // "tenant" | "global" | "none"
	ProviderName   string `json:"provider_name,omitempty"`
	HasCredentials bool   `json:"has_credentials"`
	From           string `json:"from,omitempty"`
}

type MFAAdaptiveConfig struct {
	Enabled          bool     `json:"enabled"`
	IsGlobal         bool     `json:"is_global"`
	Rules            []string `json:"rules"`
	FailureThreshold int      `json:"failure_threshold"`
	StateTTLHours    int      `json:"state_ttl_hours,omitempty"`
}

// UpdateMFAConfigRequest is used by PUT /v2/admin/tenants/{tenant_id}/mfa/config.
type UpdateMFAConfigRequest struct {
	TOTP     *UpdateTOTPConfig     `json:"totp,omitempty"`
	SMS      *UpdateSMSConfig      `json:"sms,omitempty"`
	Adaptive *UpdateAdaptiveConfig `json:"adaptive,omitempty"`
}

type UpdateTOTPConfig struct {
	Issuer string `json:"issuer"` // empty => reset to global
	Window int    `json:"window"` // 0 => reset to global
}

type UpdateSMSConfig struct {
	Provider string `json:"provider"` // "twilio" | "vonage" | ""

	TwilioAccountSID string `json:"twilio_account_sid,omitempty"`
	TwilioAuthToken  string `json:"twilio_auth_token,omitempty"`
	TwilioFrom       string `json:"twilio_from,omitempty"`

	VonageAPIKey    string `json:"vonage_api_key,omitempty"`
	VonageAPISecret string `json:"vonage_api_secret,omitempty"`
	VonageFrom      string `json:"vonage_from,omitempty"`
}

type UpdateAdaptiveConfig struct {
	UseGlobal        bool     `json:"use_global,omitempty"`
	Enabled          bool     `json:"enabled"`
	Rules            []string `json:"rules,omitempty"`
	FailureThreshold int      `json:"failure_threshold,omitempty"`
	StateTTLHours    int      `json:"state_ttl_hours,omitempty"`
}
