package auth

import (
	"context"

	emailv2 "github.com/dropDatabas3/hellojohn/internal/email"
)

// EmailVerificationSender adapts emailv2.Service to VerificationSender interface.
type EmailVerificationSender struct {
	Email emailv2.Service
}

// SendVerification sends a verification email using the email service.
func (s EmailVerificationSender) SendVerification(ctx context.Context, tenantSlugOrID, clientID, userID, email, redirect string) error {
	req := emailv2.SendVerificationRequest{
		TenantSlugOrID: tenantSlugOrID,
		ClientID:       clientID,
		UserID:         userID,
		Email:          email,
		RedirectURI:    redirect,
	}
	return s.Email.SendVerificationEmail(ctx, req)
}
