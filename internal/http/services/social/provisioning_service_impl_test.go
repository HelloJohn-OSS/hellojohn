package social

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

type socialIdentityRepoRecorder struct {
	upsertInput repository.UpsertSocialIdentityInput
	upsertUser  string
	upsertNew   bool
	upsertErr   error
	upsertCalls int
}

func (r *socialIdentityRepoRecorder) GetByProvider(context.Context, string, string, string) (*repository.SocialIdentity, error) {
	return nil, repository.ErrNotFound
}
func (r *socialIdentityRepoRecorder) GetByUserID(context.Context, string) ([]repository.SocialIdentity, error) {
	return nil, nil
}
func (r *socialIdentityRepoRecorder) Upsert(_ context.Context, input repository.UpsertSocialIdentityInput) (string, bool, error) {
	r.upsertCalls++
	r.upsertInput = input
	if r.upsertErr != nil {
		return "", false, r.upsertErr
	}
	return r.upsertUser, r.upsertNew, nil
}
func (r *socialIdentityRepoRecorder) Link(context.Context, string, repository.UpsertSocialIdentityInput) (*repository.SocialIdentity, error) {
	return nil, nil
}
func (r *socialIdentityRepoRecorder) Unlink(context.Context, string, string) error { return nil }
func (r *socialIdentityRepoRecorder) UpdateClaims(context.Context, string, map[string]any) error {
	return nil
}

type socialUserRepoRecorder struct {
	setEmailVerifiedCalls int
	setEmailVerifiedUser  string
	setEmailVerifiedValue bool
	setEmailVerifiedErr   error
}

func (r *socialUserRepoRecorder) GetByEmail(context.Context, string, string) (*repository.User, *repository.Identity, error) {
	return nil, nil, repository.ErrNotFound
}
func (r *socialUserRepoRecorder) GetByID(context.Context, string) (*repository.User, error) {
	return nil, repository.ErrNotFound
}
func (r *socialUserRepoRecorder) List(context.Context, string, repository.ListUsersFilter) ([]repository.User, error) {
	return nil, nil
}
func (r *socialUserRepoRecorder) Create(context.Context, repository.CreateUserInput) (*repository.User, *repository.Identity, error) {
	return nil, nil, nil
}
func (r *socialUserRepoRecorder) CreateBatch(context.Context, string, []repository.CreateUserInput) (int, int, error) {
	return 0, 0, nil
}
func (r *socialUserRepoRecorder) Update(context.Context, string, repository.UpdateUserInput) error {
	return nil
}
func (r *socialUserRepoRecorder) Delete(context.Context, string) error { return nil }
func (r *socialUserRepoRecorder) Disable(context.Context, string, string, string, *time.Time) error {
	return nil
}
func (r *socialUserRepoRecorder) Enable(context.Context, string, string) error { return nil }
func (r *socialUserRepoRecorder) CheckPassword(*string, string) bool           { return false }
func (r *socialUserRepoRecorder) SetEmailVerified(_ context.Context, userID string, verified bool) error {
	r.setEmailVerifiedCalls++
	r.setEmailVerifiedUser = userID
	r.setEmailVerifiedValue = verified
	return r.setEmailVerifiedErr
}
func (r *socialUserRepoRecorder) UpdatePasswordHash(context.Context, string, string) error {
	return nil
}
func (r *socialUserRepoRecorder) ListPasswordHistory(context.Context, string, int) ([]string, error) {
	return nil, nil
}
func (r *socialUserRepoRecorder) RotatePasswordHash(context.Context, string, string, int) error {
	return nil
}

func TestProvisioningService_UsesIdentityRepositoryUpsert(t *testing.T) {
	identities := &socialIdentityRepoRecorder{
		upsertUser: "user-123",
		upsertNew:  true,
	}
	users := &socialUserRepoRecorder{}
	tda := &socialTDAStub{
		slug:       "tenant-a",
		id:         "tenant-a-id",
		users:      users,
		identities: identities,
	}
	dal := &socialDALStub{tda: tda}
	svc := NewProvisioningService(ProvisioningDeps{DAL: dal})

	userID, err := svc.EnsureUserAndIdentity(context.Background(), "tenant-a", "GitLab", &OIDCClaims{
		Sub:           "provider-user-1",
		Email:         "john@example.com",
		EmailVerified: true,
		GivenName:     "John",
		FamilyName:    "Doe",
		Picture:       "https://cdn.example.com/john.png",
		Locale:        "es",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if userID != "user-123" {
		t.Fatalf("unexpected user id: %s", userID)
	}
	if identities.upsertCalls != 1 {
		t.Fatalf("expected one upsert call, got %d", identities.upsertCalls)
	}
	if identities.upsertInput.Provider != "gitlab" {
		t.Fatalf("expected provider lowercased, got %q", identities.upsertInput.Provider)
	}
	if identities.upsertInput.ProviderUserID != "provider-user-1" {
		t.Fatalf("unexpected provider user id: %q", identities.upsertInput.ProviderUserID)
	}
	if users.setEmailVerifiedCalls != 1 {
		t.Fatalf("expected email verification update, got %d calls", users.setEmailVerifiedCalls)
	}
	if users.setEmailVerifiedUser != "user-123" || !users.setEmailVerifiedValue {
		t.Fatalf("unexpected email verification update payload")
	}
}

func TestProvisioningService_RejectsMissingSubject(t *testing.T) {
	svc := NewProvisioningService(ProvisioningDeps{
		DAL: &socialDALStub{
			tda: &socialTDAStub{
				slug:       "tenant-a",
				id:         "tenant-a-id",
				identities: &socialIdentityRepoRecorder{},
			},
		},
	})

	_, err := svc.EnsureUserAndIdentity(context.Background(), "tenant-a", "google", &OIDCClaims{
		Email: "john@example.com",
	})
	if !errors.Is(err, ErrProvisioningIdentity) {
		t.Fatalf("expected ErrProvisioningIdentity, got %v", err)
	}
}

func TestProvisioningService_RequiresTenantDB(t *testing.T) {
	svc := NewProvisioningService(ProvisioningDeps{
		DAL: &socialDALStub{
			tda: &socialTDAStub{
				slug:         "tenant-a",
				id:           "tenant-a-id",
				requireDBErr: store.ErrNoDBForTenant,
			},
		},
	})

	_, err := svc.EnsureUserAndIdentity(context.Background(), "tenant-a", "google", &OIDCClaims{
		Sub:   "provider-user-1",
		Email: "john@example.com",
	})
	if !errors.Is(err, ErrProvisioningDBRequired) {
		t.Fatalf("expected ErrProvisioningDBRequired, got %v", err)
	}
}

func TestProvisioningService_IdentityUpsertError(t *testing.T) {
	identities := &socialIdentityRepoRecorder{upsertErr: errors.New("upsert failed")}
	svc := NewProvisioningService(ProvisioningDeps{
		DAL: &socialDALStub{
			tda: &socialTDAStub{
				slug:       "tenant-a",
				id:         "tenant-a-id",
				identities: identities,
				users:      &socialUserRepoRecorder{},
			},
		},
	})

	_, err := svc.EnsureUserAndIdentity(context.Background(), "tenant-a", "google", &OIDCClaims{
		Sub:   "provider-user-1",
		Email: "john@example.com",
	})
	if !errors.Is(err, ErrProvisioningIdentity) {
		t.Fatalf("expected ErrProvisioningIdentity, got %v", err)
	}
	if identities.upsertCalls != 1 {
		t.Fatalf("expected one upsert call, got %d", identities.upsertCalls)
	}
}
