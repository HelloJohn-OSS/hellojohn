package social

import "context"

type Service interface {
	Exchange(ctx context.Context, provider, code string) error
}
