package auth

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	emailv2 "github.com/dropDatabas3/hellojohn/internal/email"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

// -------------------------------------------------------------
// Fakes & Mocks
// -------------------------------------------------------------

type fakeEmailService struct {
	sentCount int
	lastEmail string
}

func (m *fakeEmailService) GetSender(ctx context.Context, tenantSlug string) (emailv2.Sender, error) {
	return m, nil
}
func (m *fakeEmailService) SendVerificationEmail(ctx context.Context, req emailv2.SendVerificationRequest) error {
	return nil
}
func (m *fakeEmailService) SendPasswordResetEmail(ctx context.Context, req emailv2.SendPasswordResetRequest) error {
	return nil
}
func (m *fakeEmailService) SendNotificationEmail(ctx context.Context, req emailv2.SendNotificationRequest) error {
	return nil
}
func (m *fakeEmailService) TestSMTP(ctx context.Context, t, e string, o *emailv2.SMTPConfig) error {
	return nil
}

func (m *fakeEmailService) Send(ctx context.Context, to string, subject string, htmlBody string, textBody string) error {
	m.sentCount++
	m.lastEmail = to
	return nil
}

type fakePasswordlessDAL struct {
	fakeDAL
	tda *fakePasswordlessTDA
}

func (d *fakePasswordlessDAL) ForTenant(ctx context.Context, tenant string) (store.TenantDataAccess, error) {
	return d.tda, nil
}

type fakePasswordlessTDA struct {
	fakeTDA
	users    *fakeUserRepository
	clients  *fakeClientRepository
	settings *repository.TenantSettings
}

func (t *fakePasswordlessTDA) Users() repository.UserRepository     { return t.users }
func (t *fakePasswordlessTDA) Clients() repository.ClientRepository { return t.clients }
func (t *fakePasswordlessTDA) Settings() *repository.TenantSettings { return t.settings }
func (t *fakePasswordlessTDA) RequireDB() error                     { return nil }
func (t *fakePasswordlessTDA) Invitations() repository.InvitationRepository {
	return nil
}
func (t *fakePasswordlessTDA) WebAuthn() repository.WebAuthnRepository { return nil }

type fakeClientRepository struct {
	client *repository.Client
}

func (r *fakeClientRepository) GetByClientID(ctx context.Context, clientID string) (*repository.Client, error) {
	return r.client, nil
}
func (r *fakeClientRepository) Get(ctx context.Context, clientID string) (*repository.Client, error) {
	return r.client, nil
}
func (r *fakeClientRepository) Create(ctx context.Context, input repository.ClientInput) (*repository.Client, error) {
	return nil, nil
}
func (r *fakeClientRepository) List(ctx context.Context, query string) ([]repository.Client, error) {
	return nil, nil
}
func (r *fakeClientRepository) Update(ctx context.Context, input repository.ClientInput) (*repository.Client, error) {
	return nil, nil
}
func (r *fakeClientRepository) Delete(context.Context, string) error { return nil }
func (r *fakeClientRepository) Authenticate(context.Context, string, string) (*repository.Client, error) {
	return nil, nil
}
func (r *fakeClientRepository) GetByUUID(ctx context.Context, uuid string) (*repository.Client, *repository.ClientVersion, error) {
	return nil, nil, nil
}
func (r *fakeClientRepository) DecryptSecret(ctx context.Context, clientID string) (string, error) {
	return "", nil
}
func (r *fakeClientRepository) ValidateClientID(id string) bool     { return true }
func (r *fakeClientRepository) ValidateRedirectURI(uri string) bool { return true }
func (r *fakeClientRepository) IsScopeAllowed(client *repository.Client, scope string) bool {
	return true
}

type fakeUserRepository struct {
	user    *repository.User
	err     error
	created bool
}

type captureAuditWriter struct {
	mu     sync.Mutex
	events []audit.AuditEvent
}

func (w *captureAuditWriter) Write(ctx context.Context, events []audit.AuditEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, events...)
	return nil
}

func (w *captureAuditWriter) Snapshot() []audit.AuditEvent {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]audit.AuditEvent, len(w.events))
	copy(out, w.events)
	return out
}

func (r *fakeUserRepository) GetByEmail(ctx context.Context, tenantID, email string) (*repository.User, *repository.Identity, error) {
	if r.err != nil {
		return nil, nil, r.err
	}
	return r.user, nil, nil
}
func (r *fakeUserRepository) Create(ctx context.Context, input repository.CreateUserInput) (*repository.User, *repository.Identity, error) {
	r.created = true
	return &repository.User{ID: "new-user-id", Email: input.Email}, nil, nil
}
func (r *fakeUserRepository) CreateBatch(ctx context.Context, tenantID string, users []repository.CreateUserInput) (int, int, error) {
	return 0, 0, nil
}
func (r *fakeUserRepository) SetEmailVerified(ctx context.Context, userID string, verified bool) error {
	return nil
}
func (r *fakeUserRepository) GetByID(context.Context, string) (*repository.User, error) {
	return nil, nil
}
func (r *fakeUserRepository) List(ctx context.Context, tenantID string, filter repository.ListUsersFilter) ([]repository.User, error) {
	return nil, nil
}
func (r *fakeUserRepository) Update(ctx context.Context, userID string, input repository.UpdateUserInput) error {
	return nil
}
func (r *fakeUserRepository) Delete(context.Context, string) error { return nil }
func (r *fakeUserRepository) Disable(ctx context.Context, id, by, reason string, until *time.Time) error {
	return nil
}
func (r *fakeUserRepository) Enable(context.Context, string, string) error             { return nil }
func (r *fakeUserRepository) CheckPassword(*string, string) bool                       { return false }
func (r *fakeUserRepository) UpdatePasswordHash(context.Context, string, string) error { return nil }
func (r *fakeUserRepository) ListPasswordHistory(context.Context, string, int) ([]string, error) {
	return nil, nil
}
func (r *fakeUserRepository) RotatePasswordHash(context.Context, string, string, int) error {
	return nil
}

// -------------------------------------------------------------
// Tests
// -------------------------------------------------------------

func TestSendMagicLink_Success(t *testing.T) {
	t.Parallel()

	memoryCache := cache.NewMemory("")
	emailSvc := &fakeEmailService{}

	tda := &fakePasswordlessTDA{
		settings: &repository.TenantSettings{
			Passwordless: &repository.PasswordlessConfig{
				MagicLink: repository.MagicLinkConfig{Enabled: true, TTLSeconds: 900},
			},
		},
		clients: &fakeClientRepository{
			client: &repository.Client{
				ClientID:     "client-a",
				RedirectURIs: []string{"https://app.example.com/callback"},
			},
		},
	}

	dal := &fakePasswordlessDAL{tda: tda}

	svc := NewPasswordlessService(PasswordlessDeps{
		DAL:     dal,
		Cache:   memoryCache,
		Email:   emailSvc,
		BaseURL: "http://localhost:3000",
	})

	err := svc.SendMagicLink(context.Background(), MagicLinkRequest{
		Email:       "User@Example.COM  ",
		TenantSlug:  "tenant-a",
		ClientID:    "client-a",
		RedirectURI: "https://app.example.com/callback",
	})

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if emailSvc.sentCount != 1 {
		t.Fatalf("expected 1 email to be sent")
	}

	// SEC-007 Fix check
	if emailSvc.lastEmail != "user@example.com" {
		t.Fatalf("expected email to be normalized")
	}
}

func TestVerifyOTP_BruteForceProtection(t *testing.T) {
	t.Parallel()

	memoryCache := cache.NewMemory("")
	emailSvc := &fakeEmailService{}

	tda := &fakePasswordlessTDA{
		settings: &repository.TenantSettings{
			Passwordless: &repository.PasswordlessConfig{
				OTP: repository.OTPConfig{Enabled: true, TTLSeconds: 300, Length: 6},
			},
		},
	}
	tda.id = "tenant-a"

	dal := &fakePasswordlessDAL{tda: tda}

	svc := NewPasswordlessService(PasswordlessDeps{
		DAL:   dal,
		Cache: memoryCache,
		Email: emailSvc,
	})

	// Pre-seed the cache with an OTP
	_ = svc.SendOTPEmail(context.Background(), OTPRequest{
		Email:      "test@example.com",
		TenantSlug: "tenant-a",
		ClientID:   "client-a",
	})

	// Fail 5 times
	for i := 0; i < 5; i++ {
		_, err := svc.VerifyOTPEmail(context.Background(), VerifyOTPRequest{
			Email:      "test@example.com",
			TenantSlug: "tenant-a",
			Code:       "000000",
		})
		if i < 4 && !strings.Contains(err.Error(), "incorrect OTP") {
			t.Fatalf("expected incorrect OTP error, got: %v", err)
		}
		if i == 4 && err.Error() != "too many failed attempts, request a new code" {
			t.Fatalf("expected lockout after 5 attempts, got: %v", err)
		}
	}

	// 6th attempt should return expired or invalid because it was purged
	_, err := svc.VerifyOTPEmail(context.Background(), VerifyOTPRequest{
		Email:      "test@example.com",
		TenantSlug: "tenant-a",
		Code:       "000000",
	})
	if err.Error() != "invalid or expired OTP" {
		t.Fatalf("expected purged OTP cache error, got: %v", err)
	}
}

func TestAutoRegister_Disabled(t *testing.T) {
	t.Parallel()

	memoryCache := cache.NewMemory("")

	tda := &fakePasswordlessTDA{
		settings: &repository.TenantSettings{
			Passwordless: &repository.PasswordlessConfig{
				OTP: repository.OTPConfig{Enabled: true, AutoRegister: false},
			},
		},
		users: &fakeUserRepository{
			err: repository.ErrNotFound,
		},
	}
	tda.id = "tenant-a"
	dal := &fakePasswordlessDAL{tda: tda}

	svc := &passwordlessService{
		deps: PasswordlessDeps{
			DAL:   dal,
			Cache: memoryCache,
		},
	}

	_, err := svc.issueJWT(context.Background(), "tenant-a", "client-a", "test@example.com", "otp")
	if err != ErrAuthenticationFailed {
		t.Fatalf("expected ErrAuthenticationFailed, got %v", err)
	}
}

func TestExchangeMagicLinkCode_EmitsLoginFailedWhenCodeMissing(t *testing.T) {
	t.Parallel()

	writer := &captureAuditWriter{}
	bus := audit.NewAuditBus(writer)
	bus.Start()

	svc := NewPasswordlessService(PasswordlessDeps{
		AuditBus: bus,
	})

	_, err := svc.ExchangeMagicLinkCode(context.Background(), "")
	if err != ErrInvalidOrExpiredMagicCode {
		t.Fatalf("expected ErrInvalidOrExpiredMagicCode, got %v", err)
	}

	bus.Stop()

	events := writer.Snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	got := events[0]
	if got.Type != audit.EventLoginFailed {
		t.Fatalf("expected %s event type, got %s", audit.EventLoginFailed, got.Type)
	}
	if got.TenantID != audit.ControlPlaneTenantID {
		t.Fatalf("expected control-plane tenant fallback, got %s", got.TenantID)
	}
	if got.Metadata["method"] != "magic_link" {
		t.Fatalf("expected method=magic_link metadata, got %+v", got.Metadata)
	}
}
