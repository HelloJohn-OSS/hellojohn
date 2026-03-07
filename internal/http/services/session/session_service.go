package session

import "context"

type Service interface {
	Login(ctx context.Context, email, password string) (sessionID string, err error)
	Logout(ctx context.Context, sessionID string) error
}
