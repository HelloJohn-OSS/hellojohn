package email

import (
	"github.com/google/uuid"
)

// VerifyEmailStartRequest is the request for POST /v2/auth/verify-email/start.
type VerifyEmailStartRequest struct {
	TenantID    string `json:"tenant_id"`
	ClientID    string `json:"client_id"`
	Email       string `json:"email,omitempty"`
	RedirectURI string `json:"redirect_uri,omitempty"`
}

// VerifyEmailConfirmRequest is parsed from query params for GET /v2/auth/verify-email.
type VerifyEmailConfirmRequest struct {
	Token       string
	RedirectURI string
	ClientID    string
	TenantID    string
}

// ForgotPasswordRequest is the request for POST /v2/auth/forgot.
type ForgotPasswordRequest struct {
	TenantID    string `json:"tenant_id"`
	ClientID    string `json:"client_id"`
	Email       string `json:"email"`
	RedirectURI string `json:"redirect_uri,omitempty"`
}

// ResetPasswordRequest is the request for POST /v2/auth/reset.
type ResetPasswordRequest struct {
	TenantID    string `json:"tenant_id"`
	ClientID    string `json:"client_id"`
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// VerifyEmailResult contains the result of email verification.
type VerifyEmailResult struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
	Redirect string
	Verified bool
}

// ResetPasswordResult contains the result of password reset.
type ResetPasswordResult struct {
	UserID       uuid.UUID
	TenantID     uuid.UUID
	AutoLogin    bool
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
}
