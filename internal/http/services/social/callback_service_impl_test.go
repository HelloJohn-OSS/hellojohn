package social

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/audit"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dtoa "github.com/dropDatabas3/hellojohn/internal/http/dto/auth"
	mw "github.com/dropDatabas3/hellojohn/internal/http/middlewares"
)

type callbackStateSignerStub struct {
	claims *StateClaims
	err    error
}

func (s callbackStateSignerStub) SignState(StateClaims) (string, error) {
	return "signed", nil
}

func (s callbackStateSignerStub) ParseState(string) (*StateClaims, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.claims, nil
}

type callbackProviderFactoryStub struct {
	client OIDCClient
	err    error
}

func (f callbackProviderFactoryStub) Build(context.Context, string, string) (OIDCClient, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.client, nil
}

type callbackOIDCClientStub struct {
	tokens *OIDCTokens
	claims *OIDCClaims
	err    error
}

func (c callbackOIDCClientStub) AuthURL(context.Context, string, string) (string, error) {
	return "", nil
}

func (c callbackOIDCClientStub) ExchangeCode(context.Context, string) (*OIDCTokens, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.tokens, nil
}

func (c callbackOIDCClientStub) VerifyIDToken(context.Context, string, string) (*OIDCClaims, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.claims, nil
}

type callbackProvisioningStub struct {
	userID string
	err    error
}

func (p callbackProvisioningStub) EnsureUserAndIdentity(context.Context, string, string, *OIDCClaims) (string, error) {
	if p.err != nil {
		return "", p.err
	}
	return p.userID, nil
}

type callbackTokenStub struct {
	resp *dtoa.LoginResponse
	err  error
}

func (t callbackTokenStub) IssueSocialTokens(context.Context, string, string, string, []string) (*dtoa.LoginResponse, error) {
	if t.err != nil {
		return nil, t.err
	}
	return t.resp, nil
}

type callbackCacheStub struct{}

func (callbackCacheStub) Get(string) ([]byte, bool) { return nil, false }
func (callbackCacheStub) Delete(string) error       { return nil }
func (callbackCacheStub) Set(string, []byte, time.Duration) {
}

type callbackClientConfigStub struct{}

func (callbackClientConfigStub) GetClient(context.Context, string, string) (*repository.Client, error) {
	return &repository.Client{ID: "client-a"}, nil
}
func (callbackClientConfigStub) ValidateRedirectURI(context.Context, string, string, string) error {
	return nil
}
func (callbackClientConfigStub) IsProviderAllowed(context.Context, string, string, string) error {
	return nil
}
func (callbackClientConfigStub) GetSocialConfig(context.Context, string, string) (*repository.SocialConfig, error) {
	return &repository.SocialConfig{}, nil
}

type callbackAuditCaptureWriter struct {
	mu     sync.Mutex
	events []audit.AuditEvent
}

func (w *callbackAuditCaptureWriter) Write(ctx context.Context, events []audit.AuditEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, events...)
	return nil
}

func (w *callbackAuditCaptureWriter) Snapshot() []audit.AuditEvent {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]audit.AuditEvent, len(w.events))
	copy(out, w.events)
	return out
}

func newCallbackServiceForTokenTests(tokenSvc TokenService, provisioning ProvisioningService) CallbackService {
	registry := NewRegistry()
	registry.Register("google", callbackProviderFactoryStub{
		client: callbackOIDCClientStub{
			tokens: &OIDCTokens{
				AccessToken: "access-token",
				IDToken:     "id-token",
			},
			claims: &OIDCClaims{
				Sub:           "provider-user",
				Email:         "john@example.com",
				EmailVerified: true,
				Name:          "John",
			},
		},
	})

	return NewCallbackService(CallbackDeps{
		StateSigner: callbackStateSignerStub{
			claims: &StateClaims{
				Provider:   "google",
				TenantSlug: "tenant-a",
				ClientID:   "client-a",
				Nonce:      "nonce-a",
			},
		},
		Cache:        callbackCacheStub{},
		LoginCodeTTL: 30 * time.Second,
		Registry:     registry,
		Provisioning: provisioning,
		TokenService: tokenSvc,
		ClientConfig: callbackClientConfigStub{},
	})
}

func TestCallbackService_TokenServiceNilReturnsError(t *testing.T) {
	service := newCallbackServiceForTokenTests(nil, callbackProvisioningStub{userID: "user-1"})

	_, err := service.Callback(context.Background(), CallbackRequest{
		Provider: "google",
		State:    "state-token",
		Code:     "auth-code",
		BaseURL:  "https://auth.example.com",
	})
	if !errors.Is(err, ErrCallbackTokenIssueFailed) {
		t.Fatalf("expected ErrCallbackTokenIssueFailed, got: %v", err)
	}
}

func TestCallbackService_TokenServiceFailureReturnsError(t *testing.T) {
	service := newCallbackServiceForTokenTests(
		callbackTokenStub{err: errors.New("token backend unavailable")},
		callbackProvisioningStub{userID: "user-1"},
	)

	_, err := service.Callback(context.Background(), CallbackRequest{
		Provider: "google",
		State:    "state-token",
		Code:     "auth-code",
		BaseURL:  "https://auth.example.com",
	})
	if !errors.Is(err, ErrCallbackTokenIssueFailed) {
		t.Fatalf("expected ErrCallbackTokenIssueFailed, got: %v", err)
	}
}

func TestCallbackService_TokenServiceFailureEmitsAuditFailure(t *testing.T) {
	writer := &callbackAuditCaptureWriter{}
	bus := audit.NewAuditBus(writer)
	bus.Start()

	registry := NewRegistry()
	registry.Register("google", callbackProviderFactoryStub{
		client: callbackOIDCClientStub{
			tokens: &OIDCTokens{
				AccessToken: "access-token",
				IDToken:     "id-token",
			},
			claims: &OIDCClaims{
				Sub:           "provider-user",
				Email:         "john@example.com",
				EmailVerified: true,
				Name:          "John",
			},
		},
	})

	service := NewCallbackService(CallbackDeps{
		StateSigner: callbackStateSignerStub{
			claims: &StateClaims{
				Provider:   "google",
				TenantSlug: "tenant-a",
				ClientID:   "client-a",
				Nonce:      "nonce-a",
			},
		},
		Cache:        callbackCacheStub{},
		LoginCodeTTL: 30 * time.Second,
		Registry:     registry,
		Provisioning: callbackProvisioningStub{userID: "user-1"},
		TokenService: callbackTokenStub{err: errors.New("token backend unavailable")},
		ClientConfig: callbackClientConfigStub{},
		AuditBus:     bus,
	})

	_, err := service.Callback(context.Background(), CallbackRequest{
		Provider: "google",
		State:    "state-token",
		Code:     "auth-code",
		BaseURL:  "https://auth.example.com",
	})
	if !errors.Is(err, ErrCallbackTokenIssueFailed) {
		t.Fatalf("expected ErrCallbackTokenIssueFailed, got: %v", err)
	}

	bus.Stop()
	events := writer.Snapshot()
	if len(events) == 0 {
		t.Fatalf("expected at least one audit event")
	}

	last := events[len(events)-1]
	if last.Type != audit.EventLoginFailed {
		t.Fatalf("expected %s event type, got %s", audit.EventLoginFailed, last.Type)
	}
	if last.Metadata["reason"] != "token_issuance_failed" {
		t.Fatalf("expected token_issuance_failed reason, got %+v", last.Metadata)
	}
	if last.TenantID != audit.ControlPlaneTenantID {
		t.Fatalf("expected %s, got %s", audit.ControlPlaneTenantID, last.TenantID)
	}
	if last.Metadata["tenant_slug"] != "tenant-a" {
		t.Fatalf("expected tenant_slug metadata, got %+v", last.Metadata)
	}
}

func TestCallbackService_TokenServiceFailureUsesResolvedTenantIDForAudit(t *testing.T) {
	writer := &callbackAuditCaptureWriter{}
	bus := audit.NewAuditBus(writer)
	bus.Start()

	registry := NewRegistry()
	registry.Register("google", callbackProviderFactoryStub{
		client: callbackOIDCClientStub{
			tokens: &OIDCTokens{
				AccessToken: "access-token",
				IDToken:     "id-token",
			},
			claims: &OIDCClaims{
				Sub:           "provider-user",
				Email:         "john@example.com",
				EmailVerified: true,
				Name:          "John",
			},
		},
	})

	service := NewCallbackService(CallbackDeps{
		StateSigner: callbackStateSignerStub{
			claims: &StateClaims{
				Provider:   "google",
				TenantSlug: "tenant-a",
				ClientID:   "client-a",
				Nonce:      "nonce-a",
			},
		},
		Cache:        callbackCacheStub{},
		LoginCodeTTL: 30 * time.Second,
		Registry:     registry,
		Provisioning: callbackProvisioningStub{userID: "user-1"},
		TokenService: callbackTokenStub{err: errors.New("token backend unavailable")},
		ClientConfig: callbackClientConfigStub{},
		AuditBus: bus,
	})

	// Inyectar TDA en el contexto para simular el middleware de tenant.
	// resolveAuditTenantID usa mw.GetTenant(ctx).ID() en lugar de TenantIDResolver.
	ctx := mw.WithTenant(context.Background(), &socialTDAStub{
		id:   "tenant-id-123",
		slug: "tenant-a",
	})
	_, err := service.Callback(ctx, CallbackRequest{
		Provider: "google",
		State:    "state-token",
		Code:     "auth-code",
		BaseURL:  "https://auth.example.com",
	})
	if !errors.Is(err, ErrCallbackTokenIssueFailed) {
		t.Fatalf("expected ErrCallbackTokenIssueFailed, got: %v", err)
	}

	bus.Stop()
	events := writer.Snapshot()
	if len(events) == 0 {
		t.Fatalf("expected at least one audit event")
	}

	last := events[len(events)-1]
	if last.TenantID != "tenant-id-123" {
		t.Fatalf("expected tenant-id-123, got %s", last.TenantID)
	}
	if last.Metadata["tenant_slug"] != "tenant-a" {
		t.Fatalf("expected tenant_slug metadata, got %+v", last.Metadata)
	}
}

func TestCallbackService_EmailMissingEmitsAuditFailure(t *testing.T) {
	writer := &callbackAuditCaptureWriter{}
	bus := audit.NewAuditBus(writer)
	bus.Start()

	registry := NewRegistry()
	registry.Register("google", callbackProviderFactoryStub{
		client: callbackOIDCClientStub{
			tokens: &OIDCTokens{
				AccessToken: "access-token",
				IDToken:     "id-token",
			},
			claims: &OIDCClaims{
				Sub:           "provider-user",
				Email:         "",
				EmailVerified: false,
				Name:          "John",
			},
		},
	})

	service := NewCallbackService(CallbackDeps{
		StateSigner: callbackStateSignerStub{
			claims: &StateClaims{
				Provider:   "google",
				TenantSlug: "tenant-a",
				ClientID:   "client-a",
				Nonce:      "nonce-a",
			},
		},
		Cache:        callbackCacheStub{},
		LoginCodeTTL: 30 * time.Second,
		Registry:     registry,
		Provisioning: callbackProvisioningStub{userID: "user-1"},
		TokenService: callbackTokenStub{resp: &dtoa.LoginResponse{AccessToken: "ok", TokenType: "Bearer", ExpiresIn: 3600}},
		ClientConfig: callbackClientConfigStub{},
		AuditBus:     bus,
	})

	_, err := service.Callback(context.Background(), CallbackRequest{
		Provider: "google",
		State:    "state-token",
		Code:     "auth-code",
		BaseURL:  "https://auth.example.com",
	})
	if !errors.Is(err, ErrCallbackEmailMissing) {
		t.Fatalf("expected ErrCallbackEmailMissing, got: %v", err)
	}

	bus.Stop()
	events := writer.Snapshot()
	if len(events) == 0 {
		t.Fatalf("expected at least one audit event")
	}

	last := events[len(events)-1]
	if last.Type != audit.EventLoginFailed {
		t.Fatalf("expected %s event type, got %s", audit.EventLoginFailed, last.Type)
	}
	if last.Metadata["reason"] != "email_missing" {
		t.Fatalf("expected email_missing reason, got %+v", last.Metadata)
	}
}
