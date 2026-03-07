package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthLogoutHandlerCSRF(t *testing.T) {
	t.Run("rejects cookie flow without csrf token", func(t *testing.T) {
		called := false
		handler := authLogoutHandler(nil, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		}))

		req := httptest.NewRequest(http.MethodPost, "/v2/auth/logout", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 when csrf token is missing, got %d", rec.Code)
		}
		if called {
			t.Fatalf("logout handler should not be called when csrf validation fails")
		}
	})

	t.Run("allows bearer flow without csrf token", func(t *testing.T) {
		called := false
		handler := authLogoutHandler(nil, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		}))

		req := httptest.NewRequest(http.MethodPost, "/v2/auth/logout", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204 for bearer flow without csrf, got %d", rec.Code)
		}
		if !called {
			t.Fatalf("logout handler should be called for bearer flow")
		}
	})
}
