// Package auth contains DTOs for MFA Email endpoints.
package auth

// SendEmailRequest is the request for POST /v2/mfa/email/send
type SendEmailRequest struct {
	MFAToken string `json:"mfa_token"`
}

// SendEmailResponse is the response for POST /v2/mfa/email/send
type SendEmailResponse struct {
	Sent      bool  `json:"sent"`
	ExpiresIn int64 `json:"expires_in"`
}

// ChallengeEmailRequest is the request for POST /v2/mfa/email/challenge
type ChallengeEmailRequest struct {
	MFAToken       string `json:"mfa_token"`
	Code           string `json:"code"`
	RememberDevice bool   `json:"remember_device,omitempty"`
}
