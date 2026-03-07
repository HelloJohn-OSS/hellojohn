package admin

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	cryptoRand "crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	controlplane "github.com/dropDatabas3/hellojohn/internal/controlplane"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	"github.com/dropDatabas3/hellojohn/internal/jwt"
)

type errReader struct{}

func (errReader) Read(_ []byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func TestGenerateOpaqueToken_ReadError(t *testing.T) {
	orig := opaqueTokenReader
	opaqueTokenReader = errReader{}
	defer func() { opaqueTokenReader = orig }()

	token, err := generateOpaqueToken()
	if err == nil {
		t.Fatalf("expected error, got token=%q", token)
	}
}

func TestAuthService_Login_EmitsAuditEvents(t *testing.T) {
	writer := &captureAuditWriter{}
	bus := audit.NewAuditBus(writer)
	bus.Start()
	defer bus.Stop()

	adminUser := &repository.Admin{
		ID:           "admin-1",
		Email:        "admin@example.com",
		PasswordHash: "secret",
		Type:         repository.AdminTypeGlobal,
	}
	cp := newFakeControlPlaneAuth(adminUser)
	issuer := newTestIssuer(t)

	svc := NewAuthService(AuthServiceDeps{
		ControlPlane: cp,
		Issuer:       issuer,
		RefreshTTL:   time.Hour,
		AuditBus:     bus,
	})

	if _, err := svc.Login(context.Background(), dto.AdminLoginRequest{
		Email:    "admin@example.com",
		Password: "wrong-secret",
	}); !errors.Is(err, ErrInvalidAdminCredentials) {
		t.Fatalf("expected ErrInvalidAdminCredentials, got %v", err)
	}

	if _, err := svc.Login(context.Background(), dto.AdminLoginRequest{
		Email:    "admin@example.com",
		Password: "secret",
	}); err != nil {
		t.Fatalf("expected login success, got %v", err)
	}

	bus.Stop()
	events := writer.Snapshot()

	failure := findEvent(events, audit.EventLoginFailed, audit.ResultFailure)
	if failure == nil {
		t.Fatalf("expected %s failure event", audit.EventLoginFailed)
	}
	if failure.TenantID != audit.ControlPlaneTenantID {
		t.Fatalf("expected tenant %q, got %q", audit.ControlPlaneTenantID, failure.TenantID)
	}
	if failure.Metadata["reason"] != "invalid_credentials" {
		t.Fatalf("expected reason invalid_credentials, got %v", failure.Metadata["reason"])
	}

	success := findEvent(events, audit.EventLogin, audit.ResultSuccess)
	if success == nil {
		t.Fatalf("expected %s success event", audit.EventLogin)
	}
	if success.ActorID != "admin-1" || success.ActorType != audit.ActorAdmin {
		t.Fatalf("unexpected success actor: %+v", success)
	}
}

func TestAuthService_Refresh_EmitsAuditEvents(t *testing.T) {
	writer := &captureAuditWriter{}
	bus := audit.NewAuditBus(writer)
	bus.Start()
	defer bus.Stop()

	adminUser := &repository.Admin{
		ID:           "admin-2",
		Email:        "admin2@example.com",
		PasswordHash: "secret",
		Type:         repository.AdminTypeGlobal,
	}
	cp := newFakeControlPlaneAuth(adminUser)
	issuer := newTestIssuer(t)

	svc := NewAuthService(AuthServiceDeps{
		ControlPlane: cp,
		Issuer:       issuer,
		RefreshTTL:   time.Hour,
		AuditBus:     bus,
	})

	loginRes, err := svc.Login(context.Background(), dto.AdminLoginRequest{
		Email:    adminUser.Email,
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("login setup failed: %v", err)
	}

	if _, err := svc.Refresh(context.Background(), dto.AdminRefreshRequest{
		RefreshToken: "invalid-token",
	}); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("expected ErrInvalidRefreshToken, got %v", err)
	}

	if _, err := svc.Refresh(context.Background(), dto.AdminRefreshRequest{
		RefreshToken: loginRes.RefreshToken,
	}); err != nil {
		t.Fatalf("expected refresh success, got %v", err)
	}

	bus.Stop()
	events := writer.Snapshot()

	failure := findEvent(events, audit.EventTokenRefreshed, audit.ResultFailure)
	if failure == nil {
		t.Fatalf("expected %s failure event", audit.EventTokenRefreshed)
	}
	if failure.Metadata["reason"] != "invalid_refresh_token" {
		t.Fatalf("expected reason invalid_refresh_token, got %v", failure.Metadata["reason"])
	}

	success := findEvent(events, audit.EventTokenRefreshed, audit.ResultSuccess)
	if success == nil {
		t.Fatalf("expected %s success event", audit.EventTokenRefreshed)
	}
	if success.ActorID != adminUser.ID {
		t.Fatalf("expected actor %q, got %q", adminUser.ID, success.ActorID)
	}
}

func findEvent(events []audit.AuditEvent, eventType audit.EventType, result string) *audit.AuditEvent {
	for i := range events {
		if events[i].Type == eventType && events[i].Result == result {
			return &events[i]
		}
	}
	return nil
}

func newTestIssuer(t *testing.T) *jwt.Issuer {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(cryptoRand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test keypair: %v", err)
	}

	repo := &testKeyRepository{
		key: &repository.SigningKey{
			ID:         "test-kid",
			Algorithm:  "EdDSA",
			PrivateKey: priv,
			PublicKey:  pub,
			Status:     repository.KeyStatusActive,
			CreatedAt:  time.Now().UTC(),
		},
	}

	return jwt.NewIssuer("http://localhost:8080", jwt.NewPersistentKeystore(repo))
}

type testKeyRepository struct {
	key *repository.SigningKey
}

func (r *testKeyRepository) GetActive(ctx context.Context, tenantID string) (*repository.SigningKey, error) {
	return r.key, nil
}

func (r *testKeyRepository) GetByKID(ctx context.Context, kid string) (*repository.SigningKey, error) {
	if kid == r.key.ID {
		return r.key, nil
	}
	return nil, repository.ErrNotFound
}

func (r *testKeyRepository) GetJWKS(ctx context.Context, tenantID string) (*repository.JWKS, error) {
	return &repository.JWKS{}, nil
}

func (r *testKeyRepository) ListAll(ctx context.Context, tenantID string) ([]*repository.SigningKey, error) {
	return []*repository.SigningKey{r.key}, nil
}

func (r *testKeyRepository) Generate(ctx context.Context, tenantID, algorithm string) (*repository.SigningKey, error) {
	return nil, repository.ErrNotImplemented
}

func (r *testKeyRepository) Rotate(ctx context.Context, tenantID string, gracePeriod time.Duration) (*repository.SigningKey, error) {
	return nil, repository.ErrNotImplemented
}

func (r *testKeyRepository) Revoke(ctx context.Context, kid string) error {
	return repository.ErrNotImplemented
}

func (r *testKeyRepository) ToEdDSA(key *repository.SigningKey) (ed25519.PrivateKey, error) {
	priv, ok := key.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("invalid key type")
	}
	return priv, nil
}

func (r *testKeyRepository) ToECDSA(key *repository.SigningKey) (*ecdsa.PrivateKey, error) {
	return nil, repository.ErrNotImplemented
}

type fakeControlPlaneAuth struct {
	controlplane.Service
	adminByEmail map[string]*repository.Admin
	adminByID    map[string]*repository.Admin
	refresh      map[string]controlplane.AdminRefreshToken
}

func newFakeControlPlaneAuth(admin *repository.Admin) *fakeControlPlaneAuth {
	adminCopy := *admin
	return &fakeControlPlaneAuth{
		adminByEmail: map[string]*repository.Admin{
			admin.Email: &adminCopy,
		},
		adminByID: map[string]*repository.Admin{
			admin.ID: &adminCopy,
		},
		refresh: make(map[string]controlplane.AdminRefreshToken),
	}
}

func (f *fakeControlPlaneAuth) GetAdminByEmail(ctx context.Context, email string) (*repository.Admin, error) {
	admin, ok := f.adminByEmail[email]
	if !ok {
		return nil, repository.ErrNotFound
	}
	out := *admin
	return &out, nil
}

func (f *fakeControlPlaneAuth) GetAdmin(ctx context.Context, id string) (*repository.Admin, error) {
	admin, ok := f.adminByID[id]
	if !ok {
		return nil, repository.ErrNotFound
	}
	out := *admin
	return &out, nil
}

func (f *fakeControlPlaneAuth) CheckAdminPassword(passwordHash, plainPassword string) bool {
	return passwordHash == plainPassword
}

func (f *fakeControlPlaneAuth) CreateAdminRefreshToken(ctx context.Context, input controlplane.AdminRefreshTokenInput) error {
	f.refresh[input.TokenHash] = controlplane.AdminRefreshToken{
		TokenHash: input.TokenHash,
		AdminID:   input.AdminID,
		ExpiresAt: input.ExpiresAt,
		CreatedAt: time.Now().UTC(),
	}
	return nil
}

func (f *fakeControlPlaneAuth) GetAdminRefreshToken(ctx context.Context, tokenHash string) (*controlplane.AdminRefreshToken, error) {
	rt, ok := f.refresh[tokenHash]
	if !ok {
		return nil, repository.ErrNotFound
	}
	out := rt
	return &out, nil
}
