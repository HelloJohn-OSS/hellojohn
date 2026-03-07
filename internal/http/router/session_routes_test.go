package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	sessionctrl "github.com/dropDatabas3/hellojohn/internal/http/controllers/session"
	sessiondto "github.com/dropDatabas3/hellojohn/internal/http/dto/session"
	sessionsvc "github.com/dropDatabas3/hellojohn/internal/http/services/session"
)

type fakeSessionTokenService struct{}

func (fakeSessionTokenService) MintFromSession(context.Context, string) (*sessionsvc.SessionTokenResult, error) {
	return &sessionsvc.SessionTokenResult{Token: "x", ExpiresIn: 60}, nil
}

func TestRegisterSessionRoutesSessionTokenToggle(t *testing.T) {
	t.Run("does not register deprecated session logout route", func(t *testing.T) {
		mux := http.NewServeMux()
		RegisterSessionRoutes(mux, SessionRouterDeps{
			Controllers: &sessionctrl.Controllers{},
		})

		req := httptest.NewRequest(http.MethodPost, "/v2/session/logout", nil)
		_, pattern := mux.Handler(req)
		if pattern != "" {
			t.Fatalf("expected no route pattern for deprecated session logout, got %q", pattern)
		}
	})

	t.Run("does not register session token route when controller is nil", func(t *testing.T) {
		mux := http.NewServeMux()
		RegisterSessionRoutes(mux, SessionRouterDeps{
			Controllers: &sessionctrl.Controllers{},
		})

		req := httptest.NewRequest(http.MethodPost, "/v2/session/token", nil)
		_, pattern := mux.Handler(req)
		if pattern != "" {
			t.Fatalf("expected no route pattern, got %q", pattern)
		}
	})

	t.Run("registers session token route when controller is present", func(t *testing.T) {
		mux := http.NewServeMux()
		tokenController := sessionctrl.NewSessionTokenController(
			fakeSessionTokenService{},
			sessiondto.LoginConfig{CookieName: "sid"},
		)

		RegisterSessionRoutes(mux, SessionRouterDeps{
			Controllers: &sessionctrl.Controllers{Token: tokenController},
		})

		req := httptest.NewRequest(http.MethodPost, "/v2/session/token", nil)
		_, pattern := mux.Handler(req)
		if pattern != "/v2/session/token" {
			t.Fatalf("expected session token route pattern, got %q", pattern)
		}
	})
}
