package mailgun

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	emailv2 "github.com/dropDatabas3/hellojohn/internal/email"
)

func TestSend_200_OK(t *testing.T) {
	s := newMailgunTestSender(t, http.StatusOK)
	err := s.Send(context.Background(), "to@example.com", "subject", "<p>hi</p>", "hi")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestSend_401(t *testing.T) {
	s := newMailgunTestSender(t, http.StatusUnauthorized)
	err := s.Send(context.Background(), "to@example.com", "subject", "<p>hi</p>", "hi")
	if !errors.Is(err, emailv2.ErrEmailAuth) {
		t.Fatalf("expected ErrEmailAuth, got %v", err)
	}
}

func TestSend_429(t *testing.T) {
	s := newMailgunTestSender(t, http.StatusTooManyRequests)
	err := s.Send(context.Background(), "to@example.com", "subject", "<p>hi</p>", "hi")
	if !errors.Is(err, emailv2.ErrEmailRateLimited) {
		t.Fatalf("expected ErrEmailRateLimited, got %v", err)
	}
}

func TestSend_400(t *testing.T) {
	s := newMailgunTestSender(t, http.StatusBadRequest)
	err := s.Send(context.Background(), "to@example.com", "subject", "<p>hi</p>", "hi")
	if !errors.Is(err, emailv2.ErrEmailRejected) {
		t.Fatalf("expected ErrEmailRejected, got %v", err)
	}
}

func TestSend_503(t *testing.T) {
	s := newMailgunTestSender(t, http.StatusServiceUnavailable)
	err := s.Send(context.Background(), "to@example.com", "subject", "<p>hi</p>", "hi")
	if !errors.Is(err, emailv2.ErrEmailTemporary) {
		t.Fatalf("expected ErrEmailTemporary, got %v", err)
	}
}

func TestBuild_RegionEU(t *testing.T) {
	raw, err := Build(emailv2.EmailProviderConfig{
		Provider:  emailv2.ProviderKindMailgun,
		FromEmail: "from@example.com",
		APIKey:    "key-test",
		Domain:    "mg.example.com",
		Region:    "eu",
	}, "")
	if err != nil {
		t.Fatalf("build sender: %v", err)
	}
	s, ok := raw.(*mailgunSender)
	if !ok {
		t.Fatalf("unexpected sender type %T", raw)
	}
	if s.baseURL != mailgunEUBaseURL {
		t.Fatalf("expected EU base URL %s, got %s", mailgunEUBaseURL, s.baseURL)
	}
}

func TestBuild_MissingDomain(t *testing.T) {
	_, err := Build(emailv2.EmailProviderConfig{
		Provider:  emailv2.ProviderKindMailgun,
		FromEmail: "from@example.com",
		APIKey:    "key-test",
	}, "")
	if !errors.Is(err, emailv2.ErrEmailConfig) {
		t.Fatalf("expected ErrEmailConfig, got %v", err)
	}
}

func newMailgunTestSender(t *testing.T, statusCode int) *mailgunSender {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v3/mg.example.com/messages" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.WriteHeader(statusCode)
	}))
	t.Cleanup(server.Close)

	raw, err := Build(emailv2.EmailProviderConfig{
		Provider:  emailv2.ProviderKindMailgun,
		FromEmail: "from@example.com",
		APIKey:    "key-test",
		Domain:    "mg.example.com",
	}, "")
	if err != nil {
		t.Fatalf("build sender: %v", err)
	}

	s, ok := raw.(*mailgunSender)
	if !ok {
		t.Fatalf("unexpected sender type %T", raw)
	}
	s.baseURL = server.URL
	s.httpClient = server.Client()
	return s
}
