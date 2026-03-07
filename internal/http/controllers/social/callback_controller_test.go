package social

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	svc "github.com/dropDatabas3/hellojohn/internal/http/services/social"
)

type callbackServiceStub struct {
	lastReq  svc.CallbackRequest
	result   *svc.CallbackResult
	callErr  error
	callSeen bool
}

func (s *callbackServiceStub) Callback(_ context.Context, req svc.CallbackRequest) (*svc.CallbackResult, error) {
	s.callSeen = true
	s.lastReq = req
	return s.result, s.callErr
}

func TestCallbackController_PostFormPost_ParsesApplePayload(t *testing.T) {
	stub := &callbackServiceStub{
		result: &svc.CallbackResult{
			RedirectURL: "https://app.example.com/callback?ok=1",
		},
	}
	controller := NewCallbackController(stub, nil)

	body := "state=signed_state&code=auth_code_123&user=%7B%22name%22%3A%7B%22firstName%22%3A%22John%22%2C%22lastName%22%3A%22Doe%22%7D%7D"
	req := httptest.NewRequest(http.MethodPost, "https://auth.example.com/v2/auth/social/apple/callback", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()

	controller.Callback(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected status %d, got %d", http.StatusFound, rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "https://app.example.com/callback?ok=1" {
		t.Fatalf("unexpected redirect location: %s", got)
	}
	if !stub.callSeen {
		t.Fatalf("expected service callback to be invoked")
	}
	if stub.lastReq.Provider != "apple" {
		t.Fatalf("expected provider apple, got %q", stub.lastReq.Provider)
	}
	if stub.lastReq.State != "signed_state" {
		t.Fatalf("expected state signed_state, got %q", stub.lastReq.State)
	}
	if stub.lastReq.Code != "auth_code_123" {
		t.Fatalf("expected code auth_code_123, got %q", stub.lastReq.Code)
	}
	if stub.lastReq.BaseURL != "https://auth.example.com" {
		t.Fatalf("expected baseURL https://auth.example.com, got %q", stub.lastReq.BaseURL)
	}
	expectedUserPayload := `{"name":{"firstName":"John","lastName":"Doe"}}`
	if stub.lastReq.UserPayload != expectedUserPayload {
		t.Fatalf("expected user payload %q, got %q", expectedUserPayload, stub.lastReq.UserPayload)
	}
}

func TestCallbackController_Get_RemainsCompatible(t *testing.T) {
	stub := &callbackServiceStub{
		result: &svc.CallbackResult{
			JSONResponse: []byte(`{"ok":true}`),
		},
	}
	controller := NewCallbackController(stub, nil)

	req := httptest.NewRequest(http.MethodGet, "https://auth.example.com/v2/auth/social/google/callback?state=s1&code=c1", nil)
	rr := httptest.NewRecorder()

	controller.Callback(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if got := strings.TrimSpace(rr.Body.String()); got != `{"ok":true}` {
		t.Fatalf("unexpected response body: %s", got)
	}
	if stub.lastReq.Provider != "google" {
		t.Fatalf("expected provider google, got %q", stub.lastReq.Provider)
	}
	if stub.lastReq.UserPayload != "" {
		t.Fatalf("expected empty user payload for GET callback, got %q", stub.lastReq.UserPayload)
	}
}

func TestCallbackController_MethodNotAllowed(t *testing.T) {
	controller := NewCallbackController(&callbackServiceStub{}, nil)

	req := httptest.NewRequest(http.MethodPut, "https://auth.example.com/v2/auth/social/google/callback", nil)
	rr := httptest.NewRecorder()

	controller.Callback(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
	if got := rr.Header().Get("Allow"); got != "GET, POST" {
		t.Fatalf("expected Allow header GET, POST, got %q", got)
	}
}
