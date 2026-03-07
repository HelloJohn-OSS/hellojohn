package social

import (
	"context"
	"errors"
	"testing"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
)

type startClientConfigStub struct {
	clientErr          error
	providerAllowedErr error
	redirectErr        error
}

func (s startClientConfigStub) GetClient(context.Context, string, string) (*repository.Client, error) {
	if s.clientErr != nil {
		return nil, s.clientErr
	}
	return &repository.Client{ID: "client-a"}, nil
}

func (s startClientConfigStub) ValidateRedirectURI(context.Context, string, string, string) error {
	return s.redirectErr
}

func (s startClientConfigStub) IsProviderAllowed(context.Context, string, string, string) error {
	return s.providerAllowedErr
}

func (s startClientConfigStub) GetSocialConfig(context.Context, string, string) (*repository.SocialConfig, error) {
	return &repository.SocialConfig{}, nil
}

type startStateSignerStub struct {
	signErr error
	state   string
}

func (s startStateSignerStub) SignState(StateClaims) (string, error) {
	if s.signErr != nil {
		return "", s.signErr
	}
	if s.state != "" {
		return s.state, nil
	}
	return "signed-state", nil
}

func (s startStateSignerStub) ParseState(string) (*StateClaims, error) {
	return nil, nil
}

type startProviderFactoryStub struct {
	client OIDCClient
	err    error
}

func (f startProviderFactoryStub) Build(context.Context, string, string) (OIDCClient, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.client, nil
}

type startOIDCClientStub struct {
	authURL string
	err     error
}

func (c startOIDCClientStub) AuthURL(context.Context, string, string) (string, error) {
	if c.err != nil {
		return "", c.err
	}
	return c.authURL, nil
}

func (c startOIDCClientStub) ExchangeCode(context.Context, string) (*OIDCTokens, error) {
	return nil, nil
}

func (c startOIDCClientStub) VerifyIDToken(context.Context, string, string) (*OIDCClaims, error) {
	return nil, nil
}

type startGenericOIDCStub struct {
	client OIDCClient
	err    error
}

func (s startGenericOIDCStub) BuildForAlias(context.Context, string, string, string) (OIDCClient, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.client, nil
}

func TestStartService_StartSuccessWithRegistry(t *testing.T) {
	registry := NewRegistry()
	registry.Register("google", startProviderFactoryStub{
		client: startOIDCClientStub{authURL: "https://provider.example.com/oauth"},
	})

	service := NewStartService(StartDeps{
		StateSigner:  startStateSignerStub{state: "state-1"},
		Registry:     registry,
		ClientConfig: startClientConfigStub{},
	})

	result, err := service.Start(context.Background(), StartRequest{
		Provider:    "google",
		TenantSlug:  "tenant-a",
		ClientID:    "client-a",
		RedirectURI: "https://app.example.com/callback",
		BaseURL:     "https://auth.example.com",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil || result.RedirectURL != "https://provider.example.com/oauth" {
		t.Fatalf("unexpected start result: %#v", result)
	}
}

func TestStartService_StartFailsWithoutClientConfig(t *testing.T) {
	service := NewStartService(StartDeps{
		StateSigner: startStateSignerStub{},
		Registry:    NewRegistry(),
	})

	_, err := service.Start(context.Background(), StartRequest{
		Provider:   "google",
		TenantSlug: "tenant-a",
		ClientID:   "client-a",
		BaseURL:    "https://auth.example.com",
	})
	if !errors.Is(err, ErrStartProviderDisabled) {
		t.Fatalf("expected ErrStartProviderDisabled, got %v", err)
	}
}

func TestStartService_StartFailsWithoutStateSigner(t *testing.T) {
	registry := NewRegistry()
	registry.Register("google", startProviderFactoryStub{
		client: startOIDCClientStub{authURL: "https://provider.example.com/oauth"},
	})

	service := NewStartService(StartDeps{
		Registry:     registry,
		ClientConfig: startClientConfigStub{},
	})

	_, err := service.Start(context.Background(), StartRequest{
		Provider:   "google",
		TenantSlug: "tenant-a",
		ClientID:   "client-a",
		BaseURL:    "https://auth.example.com",
	})
	if !errors.Is(err, ErrStartAuthURLFailed) {
		t.Fatalf("expected ErrStartAuthURLFailed, got %v", err)
	}
}

func TestStartService_StartUnknownProviderWhenNoRegistryMatch(t *testing.T) {
	service := NewStartService(StartDeps{
		StateSigner:  startStateSignerStub{},
		Registry:     NewRegistry(),
		ClientConfig: startClientConfigStub{},
	})

	_, err := service.Start(context.Background(), StartRequest{
		Provider:   "corp-sso",
		TenantSlug: "tenant-a",
		ClientID:   "client-a",
		BaseURL:    "https://auth.example.com",
	})
	if !errors.Is(err, ErrStartProviderUnknown) {
		t.Fatalf("expected ErrStartProviderUnknown, got %v", err)
	}
}

func TestStartService_StartSuccessWithGenericOIDC(t *testing.T) {
	service := NewStartService(StartDeps{
		StateSigner:  startStateSignerStub{state: "state-1"},
		Registry:     NewRegistry(),
		GenericOIDC:  startGenericOIDCStub{client: startOIDCClientStub{authURL: "https://corp.example.com/authorize"}},
		ClientConfig: startClientConfigStub{},
	})

	result, err := service.Start(context.Background(), StartRequest{
		Provider:   "corp-sso",
		TenantSlug: "tenant-a",
		ClientID:   "client-a",
		BaseURL:    "https://auth.example.com",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil || result.RedirectURL != "https://corp.example.com/authorize" {
		t.Fatalf("unexpected start result: %#v", result)
	}
}
