package claims

import (
	"context"
	"errors"
	"testing"

	"github.com/dropDatabas3/hellojohn/internal/claims/resolver"
)

// mockResolver emula resolve success o failure
type mockResolver struct {
	name      string
	val       any
	errReturn error
}

func (m *mockResolver) Name() string { return m.name }
func (m *mockResolver) Resolve(ctx context.Context, input resolver.ResolverInput) (any, error) {
	if m.errReturn != nil {
		return nil, m.errReturn
	}
	return m.val, nil
}

func TestEnforceNamespace(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"roles", "https://hellojohn.dev/claims/roles"},
		{"https://mycompany.com/id", "https://mycompany.com/id"},
		{"urn:oidc:uid", "urn:oidc:uid"},
		{"is_premium", "https://hellojohn.dev/claims/is_premium"},
	}

	for _, tc := range tests {
		if got := EnforceNamespace(tc.in); got != tc.want {
			t.Errorf("EnforceNamespace(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestClaimsHook_ResolveAll(t *testing.T) {
	resolvers := map[string]resolver.Resolver{
		"mock1": &mockResolver{name: "mock1", val: "success_val1"},
		"mock2": &mockResolver{name: "mock2", val: "success_val2"},
		"fail":  &mockResolver{name: "fail", errReturn: errors.New("timeout")},
		"null":  &mockResolver{name: "null", val: nil},
	}

	tests := []struct {
		name        string
		reqScopes   []string
		configs     []ClaimConfig
		wantErr     bool
		wantKeys    []string
		wantNotKeys []string
	}{
		{
			name:      "Scope match merges properties enforcing namespace",
			reqScopes: []string{"profile", "email"},
			configs: []ClaimConfig{
				{ClaimName: "custom_prop", ResolverType: "mock1", Scopes: []string{"profile"}},
				{ClaimName: "https://x.com/c", ResolverType: "mock2", Scopes: []string{"email"}},
			},
			wantKeys: []string{"https://hellojohn.dev/claims/custom_prop", "https://x.com/c"},
		},
		{
			name:      "Ignores resolvers with unfulfilled scopes",
			reqScopes: []string{"email"}, // Pide email
			configs: []ClaimConfig{
				{ClaimName: "allowed", ResolverType: "mock1", Scopes: []string{"email"}},
				{ClaimName: "ignored", ResolverType: "mock2", Scopes: []string{"profile"}}, // Requiere profile
			},
			wantKeys:    []string{"https://hellojohn.dev/claims/allowed"},
			wantNotKeys: []string{"https://hellojohn.dev/claims/ignored"},
		},
		{
			name:      "Global resolver executes without scopes check",
			reqScopes: []string{"offline_access"},
			configs: []ClaimConfig{
				{ClaimName: "global", ResolverType: "mock1"}, // Sin limitantes de scope
			},
			wantKeys: []string{"https://hellojohn.dev/claims/global"},
		},
		{
			name:      "Fail-Open continues execution",
			reqScopes: []string{"profile"},
			configs: []ClaimConfig{
				{ClaimName: "failed_but_open", ResolverType: "fail", Required: false},
				{ClaimName: "success", ResolverType: "mock1"},
			},
			wantKeys:    []string{"https://hellojohn.dev/claims/success"},
			wantNotKeys: []string{"https://hellojohn.dev/claims/failed_but_open"},
		},
		{
			name:      "Fail-Closed aborts login process",
			reqScopes: []string{"profile"},
			configs: []ClaimConfig{
				{ClaimName: "mandatory", ResolverType: "fail", Required: true},
				{ClaimName: "success", ResolverType: "mock1"},
			},
			wantErr: true,
		},
		{
			name:      "Nil results drop from root map cleanly",
			reqScopes: []string{"profile"},
			configs: []ClaimConfig{
				{ClaimName: "empty", ResolverType: "null"},
			},
			wantNotKeys: []string{"https://hellojohn.dev/claims/empty"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hook := NewClaimsHook(tc.configs, resolvers)
			res, err := hook.ResolveAll(context.Background(), resolver.ResolverInput{Scopes: tc.reqScopes})

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for Fail-Close, got none")
				}
				return // Detener validación
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for _, wantK := range tc.wantKeys {
				if _, ok := res[wantK]; !ok {
					t.Errorf("missing expected key in JWT payload: %s", wantK)
				}
			}

			for _, notWantK := range tc.wantNotKeys {
				if _, ok := res[notWantK]; ok {
					t.Errorf("found unallowed key in JWT payload: %s", notWantK)
				}
			}
		})
	}
}
