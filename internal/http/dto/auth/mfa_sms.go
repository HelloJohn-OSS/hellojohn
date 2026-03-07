// Package auth contains DTOs for MFA SMS endpoints.
package auth

// SendSMSRequest is the request for POST /v2/mfa/sms/send
type SendSMSRequest struct {
	MFAToken string `json:"mfa_token"`
}

// SendSMSResponse is the response for POST /v2/mfa/sms/send
type SendSMSResponse struct {
	Sent      bool  `json:"sent"`
	ExpiresIn int64 `json:"expires_in"`
}

// ChallengeSMSRequest is the request for POST /v2/mfa/sms/challenge
type ChallengeSMSRequest struct {
	MFAToken       string `json:"mfa_token"`
	Code           string `json:"code"`
	RememberDevice bool   `json:"remember_device,omitempty"`
}
