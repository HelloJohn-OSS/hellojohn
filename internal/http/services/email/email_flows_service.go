package email

import "context"

// EmailFlows unifica verify/forgot/reset.
type EmailFlows interface {
	StartVerify(ctx context.Context, email string) error
	ConfirmVerify(ctx context.Context, token string) error
	StartForgot(ctx context.Context, email string) error
	ConfirmReset(ctx context.Context, token, password string) error
}
