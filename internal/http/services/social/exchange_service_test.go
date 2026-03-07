package social

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/social"
)

type exchangeCacheStub struct {
	data       map[string][]byte
	deleteErr  error
	deleteHits int
}

func (c *exchangeCacheStub) Get(key string) ([]byte, bool) {
	v, ok := c.data[key]
	return v, ok
}

func (c *exchangeCacheStub) Delete(key string) error {
	c.deleteHits++
	if c.deleteErr != nil {
		return c.deleteErr
	}
	delete(c.data, key)
	return nil
}

type exchangeClientConfigStub struct {
	getClientErr error
	allowErr     error
}

func (s exchangeClientConfigStub) GetClient(context.Context, string, string) (*repository.Client, error) {
	if s.getClientErr != nil {
		return nil, s.getClientErr
	}
	return &repository.Client{ID: "client-a"}, nil
}
func (s exchangeClientConfigStub) ValidateRedirectURI(context.Context, string, string, string) error {
	return nil
}
func (s exchangeClientConfigStub) IsProviderAllowed(context.Context, string, string, string) error {
	return s.allowErr
}
func (s exchangeClientConfigStub) GetSocialConfig(context.Context, string, string) (*repository.SocialConfig, error) {
	return &repository.SocialConfig{}, nil
}

func TestExchangeService_ValidatesInputs(t *testing.T) {
	service := NewExchangeService(ExchangeDeps{
		Cache: &exchangeCacheStub{data: map[string][]byte{}},
	})

	_, err := service.Exchange(context.Background(), dto.ExchangeRequest{})
	if !errors.Is(err, ErrCodeMissing) {
		t.Fatalf("expected ErrCodeMissing, got %v", err)
	}

	_, err = service.Exchange(context.Background(), dto.ExchangeRequest{Code: "code-a"})
	if !errors.Is(err, ErrClientMissing) {
		t.Fatalf("expected ErrClientMissing, got %v", err)
	}
}

func TestExchangeService_CodeNotFound(t *testing.T) {
	service := NewExchangeService(ExchangeDeps{
		Cache: &exchangeCacheStub{data: map[string][]byte{}},
	})

	_, err := service.Exchange(context.Background(), dto.ExchangeRequest{
		Code:     "missing",
		ClientID: "client-a",
	})
	if !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("expected ErrCodeNotFound, got %v", err)
	}
}

func TestExchangeService_InvalidPayload(t *testing.T) {
	cache := &exchangeCacheStub{
		data: map[string][]byte{
			"social:code:bad-json": []byte("not-json"),
		},
	}
	service := NewExchangeService(ExchangeDeps{Cache: cache})

	_, err := service.Exchange(context.Background(), dto.ExchangeRequest{
		Code:     "bad-json",
		ClientID: "client-a",
	})
	if !errors.Is(err, ErrPayloadInvalid) {
		t.Fatalf("expected ErrPayloadInvalid, got %v", err)
	}
}

func TestExchangeService_ClientAndTenantMismatch(t *testing.T) {
	stored := dto.ExchangePayload{
		ClientID:   "client-a",
		TenantID:   "tenant-a",
		TenantSlug: "tenant-a",
		Provider:   "google",
	}
	payload, _ := json.Marshal(stored)
	cache := &exchangeCacheStub{
		data: map[string][]byte{"social:code:code-a": payload},
	}
	service := NewExchangeService(ExchangeDeps{Cache: cache})

	_, err := service.Exchange(context.Background(), dto.ExchangeRequest{
		Code:     "code-a",
		ClientID: "client-b",
	})
	if !errors.Is(err, ErrClientMismatch) {
		t.Fatalf("expected ErrClientMismatch, got %v", err)
	}

	_, err = service.Exchange(context.Background(), dto.ExchangeRequest{
		Code:     "code-a",
		ClientID: "client-a",
		TenantID: "tenant-b",
	})
	if !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("expected ErrTenantMismatch, got %v", err)
	}
}

func TestExchangeService_HardenedValidationErrors(t *testing.T) {
	stored := dto.ExchangePayload{
		ClientID:   "client-a",
		TenantID:   "tenant-a",
		TenantSlug: "tenant-a",
		Provider:   "google",
	}
	payload, _ := json.Marshal(stored)

	cache := &exchangeCacheStub{
		data: map[string][]byte{"social:code:code-a": payload},
	}
	service := NewExchangeService(ExchangeDeps{
		Cache: cache,
		ClientConfig: exchangeClientConfigStub{
			getClientErr: ErrClientNotFound,
		},
	})

	_, err := service.Exchange(context.Background(), dto.ExchangeRequest{
		Code:     "code-a",
		ClientID: "client-a",
	})
	if !errors.Is(err, ErrClientMismatch) {
		t.Fatalf("expected ErrClientMismatch, got %v", err)
	}

	cache.data["social:code:code-b"] = payload
	service = NewExchangeService(ExchangeDeps{
		Cache: cache,
		ClientConfig: exchangeClientConfigStub{
			allowErr: ErrProviderNotAllowed,
		},
	})

	_, err = service.Exchange(context.Background(), dto.ExchangeRequest{
		Code:     "code-b",
		ClientID: "client-a",
	})
	if !errors.Is(err, ErrExchangeProviderNotAllowed) {
		t.Fatalf("expected ErrExchangeProviderNotAllowed, got %v", err)
	}
}

func TestExchangeService_SuccessConsumesCode(t *testing.T) {
	stored := dto.ExchangePayload{
		ClientID:   "client-a",
		TenantID:   "tenant-a",
		TenantSlug: "tenant-a",
		Provider:   "google",
	}
	payload, _ := json.Marshal(stored)
	cache := &exchangeCacheStub{
		data: map[string][]byte{"social:code:code-a": payload},
	}
	service := NewExchangeService(ExchangeDeps{
		Cache:        cache,
		ClientConfig: exchangeClientConfigStub{},
	})

	result, err := service.Exchange(context.Background(), dto.ExchangeRequest{
		Code:     "code-a",
		ClientID: "client-a",
		TenantID: "tenant-a",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result == nil || result.ClientID != "client-a" {
		t.Fatalf("unexpected exchange result: %#v", result)
	}
	if cache.deleteHits != 1 {
		t.Fatalf("expected one cache delete, got %d", cache.deleteHits)
	}
	if _, ok := cache.data["social:code:code-a"]; ok {
		t.Fatalf("expected code to be consumed from cache")
	}
}

func TestExchangeService_AcceptsTenantSlugForBackwardCompatibility(t *testing.T) {
	stored := dto.ExchangePayload{
		ClientID:   "client-a",
		TenantID:   "tenant-id-123",
		TenantSlug: "tenant-a",
		Provider:   "google",
	}
	payload, _ := json.Marshal(stored)
	cache := &exchangeCacheStub{
		data: map[string][]byte{"social:code:code-a": payload},
	}
	service := NewExchangeService(ExchangeDeps{
		Cache:        cache,
		ClientConfig: exchangeClientConfigStub{},
	})

	_, err := service.Exchange(context.Background(), dto.ExchangeRequest{
		Code:     "code-a",
		ClientID: "client-a",
		TenantID: "tenant-a",
	})
	if err != nil {
		t.Fatalf("expected slug tenant_id to be accepted, got %v", err)
	}
}
