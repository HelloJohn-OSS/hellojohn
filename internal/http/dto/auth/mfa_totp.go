// Package auth contains DTOs for MFA TOTP endpoints.
package auth

// EnrollTOTPResponse is the response for POST /v2/mfa/totp/enroll
type EnrollTOTPResponse struct {
	SecretBase32 string `json:"secret_base32"`
	OTPAuthURL   string `json:"otpauth_url"`
}

// VerifyTOTPRequest is the request for POST /v2/mfa/totp/verify
type VerifyTOTPRequest struct {
	Code string `json:"code"`
}

// VerifyTOTPResponse is the response for POST /v2/mfa/totp/verify
type VerifyTOTPResponse struct {
	Enabled       bool     `json:"enabled"`
	RecoveryCodes []string `json:"recovery_codes,omitempty"`
}

// ChallengeTOTPRequest is the request for POST /v2/mfa/totp/challenge
type ChallengeTOTPRequest struct {
	MFAToken       string `json:"mfa_token"`
	Code           string `json:"code,omitempty"`
	Recovery       string `json:"recovery,omitempty"`
	RememberDevice bool   `json:"remember_device,omitempty"`
}

// ChallengeTOTPResponse is the response for POST /v2/mfa/totp/challenge
type ChallengeTOTPResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// DisableTOTPRequest is the request for POST /v2/mfa/totp/disable
type DisableTOTPRequest struct {
	Password string `json:"password"`
	Code     string `json:"code,omitempty"`
	Recovery string `json:"recovery,omitempty"`
}

// DisableTOTPResponse is the response for POST /v2/mfa/totp/disable
type DisableTOTPResponse struct {
	Disabled bool `json:"disabled"`
}

// RotateRecoveryRequest is the request for POST /v2/mfa/recovery/rotate
type RotateRecoveryRequest struct {
	Password string `json:"password"`
	Code     string `json:"code,omitempty"`
	Recovery string `json:"recovery,omitempty"`
}

// RotateRecoveryResponse is the response for POST /v2/mfa/recovery/rotate
type RotateRecoveryResponse struct {
	Rotated       bool     `json:"rotated"`
	RecoveryCodes []string `json:"recovery_codes"`
}
