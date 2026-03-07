package social

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

type socialTokenRepoRecorder struct {
	createInput repository.CreateRefreshTokenInput
	createErr   error
	createCalls int
}

func (r *socialTokenRepoRecorder) Create(_ context.Context, input repository.CreateRefreshTokenInput) (string, error) {
	r.createCalls++
	r.createInput = input
	if r.createErr != nil {
		return "", r.createErr
	}
	return "rt-1", nil
}
func (r *socialTokenRepoRecorder) GetByHash(context.Context, string) (*repository.RefreshToken, error) {
	return nil, repository.ErrNotFound
}
func (r *socialTokenRepoRecorder) GetByID(context.Context, string) (*repository.RefreshToken, error) {
	return nil, repository.ErrNotFound
}
func (r *socialTokenRepoRecorder) Revoke(context.Context, string) error { return nil }
func (r *socialTokenRepoRecorder) GetFamilyRoot(context.Context, string) (string, error) {
	return "", nil
}
func (r *socialTokenRepoRecorder) RevokeFamily(context.Context, string) error { return nil }
func (r *socialTokenRepoRecorder) RevokeAllByUser(context.Context, string, string) (int, error) {
	return 0, nil
}
func (r *socialTokenRepoRecorder) RevokeAllByClient(context.Context, string) error { return nil }
func (r *socialTokenRepoRecorder) List(context.Context, repository.ListTokensFilter) ([]repository.RefreshToken, error) {
	return nil, nil
}
func (r *socialTokenRepoRecorder) Count(context.Context, repository.ListTokensFilter) (int, error) {
	return 0, nil
}
func (r *socialTokenRepoRecorder) RevokeAll(context.Context) (int, error) { return 0, nil }
func (r *socialTokenRepoRecorder) GetStats(context.Context) (*repository.TokenStats, error) {
	return nil, nil
}

func TestStoreRefreshToken_UsesTenantTokenRepository(t *testing.T) {
	repo := &socialTokenRepoRecorder{}
	tda := &socialTDAStub{
		id:           "tenant-a",
		requireDBErr: nil,
		tokens:       repo,
	}
	svc := &tokenService{refreshTTL: 12 * time.Hour}

	err := svc.storeRefreshToken(context.Background(), tda, "user-1", "client-1", "refresh-token-plain")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if repo.createCalls != 1 {
		t.Fatalf("expected token repo Create to be called once, got %d", repo.createCalls)
	}
	if repo.createInput.UserID != "user-1" || repo.createInput.ClientID != "client-1" {
		t.Fatalf("unexpected create input user/client: %#v", repo.createInput)
	}
	if repo.createInput.TenantID != "tenant-a" {
		t.Fatalf("unexpected tenant id, got %q", repo.createInput.TenantID)
	}
	if repo.createInput.TokenHash == "" || repo.createInput.TokenHash == "refresh-token-plain" {
		t.Fatalf("expected hashed token, got %q", repo.createInput.TokenHash)
	}
	if repo.createInput.TTLSeconds != int((12 * time.Hour).Seconds()) {
		t.Fatalf("unexpected ttl seconds: %d", repo.createInput.TTLSeconds)
	}
}

func TestStoreRefreshToken_RequiresTenantDB(t *testing.T) {
	tda := &socialTDAStub{
		id:           "tenant-a",
		requireDBErr: store.ErrNoDBForTenant,
		tokens:       &socialTokenRepoRecorder{},
	}
	svc := &tokenService{refreshTTL: time.Hour}

	err := svc.storeRefreshToken(context.Background(), tda, "user-1", "client-1", "refresh-token-plain")
	if !errors.Is(err, ErrRefreshStoreFailed) {
		t.Fatalf("expected ErrRefreshStoreFailed, got %v", err)
	}
}

func TestStoreRefreshToken_PropagatesRepositoryErrors(t *testing.T) {
	repo := &socialTokenRepoRecorder{createErr: errors.New("insert failed")}
	tda := &socialTDAStub{
		id:           "tenant-a",
		requireDBErr: nil,
		tokens:       repo,
	}
	svc := &tokenService{refreshTTL: time.Hour}

	err := svc.storeRefreshToken(context.Background(), tda, "user-1", "client-1", "refresh-token-plain")
	if !errors.Is(err, ErrRefreshStoreFailed) {
		t.Fatalf("expected ErrRefreshStoreFailed, got %v", err)
	}
	if repo.createCalls != 1 {
		t.Fatalf("expected token repo Create to be called once, got %d", repo.createCalls)
	}
}
