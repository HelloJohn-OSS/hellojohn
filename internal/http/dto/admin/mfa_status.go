package admin

// MFAStatusResponse is returned by GET /v2/admin/tenants/{tenant_id}/mfa/status.
type MFAStatusResponse struct {
	MFAEnabled  bool        `json:"mfa_enabled"`
	MFARequired bool        `json:"mfa_required"`
	Methods     MFAMethods  `json:"methods"`
	Adaptive    MFAAdaptive `json:"adaptive"`
}

type MFAMethods struct {
	TOTP  MFATOTPStatus  `json:"totp"`
	SMS   MFASMSStatus   `json:"sms"`
	Email MFAEmailStatus `json:"email"`
}

// MFATOTPStatus describes TOTP availability.
// TOTP is always available because it does not require tenant-level provider setup.
type MFATOTPStatus struct {
	Available bool `json:"available"`
}

// MFASMSStatus describes SMS availability for this tenant.
// Provider values: "global" | "tenant" | "none".
type MFASMSStatus struct {
	Available    bool   `json:"available"`
	Provider     string `json:"provider"`
	ProviderName string `json:"provider_name,omitempty"`
}

// MFAEmailStatus describes email OTP availability for this tenant.
type MFAEmailStatus struct {
	Available      bool `json:"available"`
	SMTPConfigured bool `json:"smtp_configured"`
}

// MFAAdaptive describes adaptive MFA engine state.
type MFAAdaptive struct {
	Enabled          bool     `json:"enabled"`
	Rules            []string `json:"rules,omitempty"`
	FailureThreshold int      `json:"failure_threshold,omitempty"`
}
